package util

import (
	"os"
	"time"
)

type Config struct {
	prefix           string
	keyLength        uint
	secretKeyFolder  string
	sequenceInterval time.Duration
}

func (c *Config) Prefix() string {
	return c.prefix
}

func (c *Config) KeyLength() uint {
	return c.keyLength
}
func (c *Config) SecretKeyFolder() string {
	return c.secretKeyFolder
}

func (c *Config) SequenceInterval() time.Duration {
	return c.sequenceInterval
}

const (
	CONFIG_FILE = "config.ini"
)

var config *Config

func init() {

	if Exists(CONFIG_FILE) {
		// load the config file here I guess
	} else {
		config = &Config{ // default config
			prefix:           "thered",
			keyLength:        64,
			secretKeyFolder:  "secrets/",
			sequenceInterval: 30 * time.Second,
		}
	}
}

func Exists(path string) bool {
	file, err := os.Stat(path)
	if err == nil && !file.IsDir() {
		return true
	}
	return false
}
