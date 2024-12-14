package totp_manager

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const (
	Prefix    = "thered"
	KeyLength = 64
)

type totp struct {
	secret          [KeyLength]byte
	currentSequence []int
}

var loadedTotps []totp
var once sync.Once
var onceErr error

func ReadSecrets() ([][]byte, error) {
	var files []string

	err := filepath.Walk("secrets/", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && filepath.Ext(info.Name()) == Prefix {
			files = append(files, path)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk through folder: %w", err)
	}

	keys := make([][]byte, 0, len(files))

	for _, filename := range files {
		key, err := os.ReadFile(filename)
		if err != nil {
			fmt.Printf("Error reading key from %s: %v\n", filename, err)
			continue
		}

		if len(key) != KeyLength {
			fmt.Printf("Error: Key in %s is not %d bytes (got %d bytes)\n", filename, keyLength, len(key))
			continue
		}

		keys = append(keys, key)
	}

	fmt.Printf("Read %d of %d keys succssfully\n", len(keys), len(files))

	return keys, nil
}

func getLoaded() ([]totp, error) {
	once.Do(func() {
		secrets, err := ReadSecrets()

		if err != nil {
			onceErr = fmt.Errorf("failed to load totp secrets: %w", err)
			return
		}

		// port sequence will be a function call
		for _, s := range secrets {
			loadedTotps = append(loadedTotps, totp{s, []int{1, 2, 3}})
		}
	})

	if onceErr != nil {
		return nil, onceErr
	}

	return loadedTotps, nil
}

func checkTotp(sequence []int) {

}
