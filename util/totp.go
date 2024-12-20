package totp_manager

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// change this so it's loaded from a config file?
const (
	Prefix          = "thered"
	KeyLength       = 64
	SecretKeyFolder = "secrets/"
)

type totp struct {
	secret          [KeyLength]byte
	currentSequence []uint16
	used            bool
	mu              sync.Mutex
}

var loadedTotps []totp
var ticker time.Ticker

var once sync.Once
var onceErr error

func CalculateSequence(secret [KeyLength]byte) []uint16 {
	hasher := sha512.New()

	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, uint64(time.Now().Unix())/30)

	hasher.Write(secret[:])
	hasher.Write(counter[:])

	hash := hasher.Sum(nil)
	ports := []uint16{}

	for i := 0; i < len(hash)/2; i++ {
		// SHA-512 always generates a 64-byte hash (therefore even)
		portValue := binary.BigEndian.Uint16(hash[i*2 : (i+1)*2])
		ports = append(ports, uint16(portValue))
	}
	return ports
}

func (t *totp) UpdateSequence() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.currentSequence = CalculateSequence(t.secret)
}

func (t *totp) GetSequence() []uint16 {
	t.mu.Lock()
	defer t.mu.Unlock()

	sequenceCopy := make([]uint16, len(t.currentSequence))
	copy(sequenceCopy, t.currentSequence)
	return sequenceCopy
}

func (t *totp) SetUsed() { // this will be set to false when the sequence is changed
	t.mu.Lock()
	defer t.mu.Unlock()
	t.used = true
}

func ReadSecrets() ([][KeyLength]byte, error) {
	var files []string

	err := filepath.Walk(SecretKeyFolder, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && filepath.Ext(info.Name()) == "."+Prefix {
			files = append(files, path)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk through folder: %w", err)
	}

	keys := make([][KeyLength]byte, 0, len(files))

	for _, filename := range files {
		key, err := os.ReadFile(filename)
		if err != nil {
			fmt.Printf("Error reading key from %s: %v\n", filename, err)
			continue
		}

		if len(key) != KeyLength {
			fmt.Printf("Error: Key in %s is not %d bytes (got %d bytes)\n", filename, KeyLength, len(key))
			continue
		}

		// I don't like this
		var fixed [KeyLength]byte
		copy(fixed[:], key)

		keys = append(keys, fixed)
	}

	fmt.Printf("Read %d of %d keys succssfully\n", len(keys), len(files))

	return keys, nil
}

func CheckSequence(sequence []uint16) (bool, error) {

	if len(sequence) < 1 {
		return false, fmt.Errorf("length of sequence: %d", len(sequence))
	}

	once.Do(func() {
		secrets, err := ReadSecrets()

		if err != nil {
			onceErr = fmt.Errorf("failed to load totp secrets: %w", err)
			return
		}

		for _, s := range secrets {
			loadedTotps = append(loadedTotps, totp{s, CalculateSequence(s), false, sync.Mutex{}})
		}
	})

	if onceErr != nil {
		return false, onceErr
	}

	for i := range loadedTotps {

		if loadedTotps[i].used { // check if I need to add a GetUsed method
			continue
		}

		testSequence := loadedTotps[i].GetSequence()

		sequenceLength := len(testSequence) // this could be a hardcoded value, but just incase.

		if len(testSequence) > len(sequence) {
			testSequence = testSequence[0:len(sequence)]
		} else {
			return false, fmt.Errorf("sequence longer than expected (%d), found %d", sequenceLength, len(sequence))
		}

		testSequence = testSequence[0:len(sequence)]

		fmt.Printf("Checking if %v like %v\n", sequence, testSequence)

		isValid := slices.Equal(sequence, testSequence)

		if isValid {

			if len(sequence) == sequenceLength {
				loadedTotps[i].SetUsed()
			}

			return true, nil
		}
	}

	return false, nil
}
