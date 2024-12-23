package util

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// change this so it's loaded from a config file?
const (
	Prefix           = "thered"
	KeyLength        = 64
	SecretKeyFolder  = "secrets/"
	SequenceInterval = 30 * time.Second
)

type totp struct {
	secret          [KeyLength]byte
	currentSequence []uint16
	lastUpdated     time.Time

	// the only downside of this is a port can only be opened once every 30 seconds
	used bool
}

var loadedTotps []totp

var once sync.Once
var onceErr error

func CalculateSequence(t time.Time, secret [KeyLength]byte) []uint16 {
	hasher := sha512.New()

	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, uint64(t.Unix())/30)

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

func (t *totp) Update() bool {

	thyme := t.lastUpdated.Truncate(SequenceInterval)

	if time.Since(thyme) < SequenceInterval {
		return false
	}

	wibblywobbly := time.Now()

	t.lastUpdated = wibblywobbly
	t.currentSequence = CalculateSequence(wibblywobbly, t.secret)
	t.used = false

	return true
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
			continue
		}

		if len(key) < KeyLength {
			continue
		}

		// I don't like this
		var fixed [KeyLength]byte
		copy(fixed[:], key[0:KeyLength])

		keys = append(keys, fixed)
	}
	return keys, nil
}

func CheckSequence(sequence []uint16) (bool, error) {

	if len(sequence) < 1 {
		return false, nil
	}

	once.Do(func() {
		secrets, err := ReadSecrets()

		if err != nil {
			onceErr = fmt.Errorf("failed to load totp secrets: %w", err)
			return
		}

		t := time.Now()
		for _, s := range secrets {
			loadedTotps = append(loadedTotps, totp{s, CalculateSequence(t, s), t, false})
		}
	})

	if onceErr != nil {
		return false, onceErr
	}

	for i := range loadedTotps {

		if loadedTotps[i].used {
			continue
		}

		/*
		 * This check's if the totp sequence needs updating and returns true if the sequence is updated
		 * if the sequence has been updated and this check isn't for the first element - return false
		 */

		if loadedTotps[i].Update() && len(sequence) != 1 {
			return false, nil
		}

		sequenceLength := len(loadedTotps[i].currentSequence)

		var testSequence []uint16
		if sequenceLength >= len(sequence) {
			testSequence = loadedTotps[i].currentSequence[0:len(sequence)]
		} else {
			return false, fmt.Errorf("sequence longer than expected (%d), found %d", sequenceLength, len(sequence))
		}

		isValid := slices.Equal(sequence, testSequence)

		if isValid {

			if len(sequence) == sequenceLength {
				loadedTotps[i].used = true
			}

			return true, nil
		}
	}

	return false, nil
}

func GenerateSecret() (string, error) {
	key := make([]byte, KeyLength)
	_, err := rand.Read(key)
	if err != nil {
		return "", fmt.Errorf("couldn't create key: %w", err)
	}
	return hex.EncodeToString(key), nil
}
