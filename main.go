package main

import (
	"fmt"
	"net/netip"
	"sync"
	"time"
)

type KnockAttempt struct {
	firstKnock    time.Time
	knockSequence []int
}

var currentAttempts sync.Map // Using sync.Map for thread-safe operations

// Function to round time to the nearest 30 seconds
func roundToNearestTime(t time.Time) time.Time {
	sinceMidnight := t.Hour()*3600 + t.Minute()*60 + t.Second()
	nearest := (sinceMidnight + 15) / 30 * 30
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, nearest, 0, t.Location())
}

// Function to remove invalid attempts from the map
func removeInvalidAttempts() {
	currentAttempts.Range(func(key, value interface{}) bool {
		addr := key.(netip.Addr)
		attempt := value.(KnockAttempt)

		rounded := roundToNearestTime(attempt.firstKnock)
		if time.Since(rounded) >= 30*time.Second {
			fmt.Println("Removing", addr)
			currentAttempts.Delete(addr)
		}
		return true // Continue iteration
	})
}

// Function to add an attempt to the map
func addAttempt(addr netip.Addr, attempt KnockAttempt) {
	currentAttempts.Store(addr, attempt)
}

func main() {
	fmt.Println("Hello, World!")

	// Ticker goroutine to remove invalid attempts every 30 seconds
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				removeInvalidAttempts()
			}
		}
	}()

	// Simulate adding entries to the map
	go func() {
		for i := 0; i < 10; i++ {
			addr, _ := netip.ParseAddr(fmt.Sprintf("192.168.0.%d", i))
			addAttempt(addr, KnockAttempt{
				firstKnock:    time.Now(),
				knockSequence: []int{1, 2, 3},
			})
			time.Sleep(5 * time.Second)
		}
	}()

	// Keep the program running
	select {}
}
