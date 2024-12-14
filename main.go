package main

// ignore this file for now.

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

var currentAttempts sync.Map

func removeInvalidAttempts() {
	currentAttempts.Range(func(key, value interface{}) bool {
		addr := key.(netip.Addr)
		attempt := value.(KnockAttempt)

		rounded := attempt.firstKnock.Truncate(30 * time.Second)
		if time.Since(rounded) >= 30*time.Second {
			fmt.Println("Removing", addr)
			currentAttempts.Delete(addr)
		}
		return true // Continue iteration
	})
}

func addAttempt(addr netip.Addr, attempt KnockAttempt) {
	currentAttempts.Store(addr, attempt)
}

func main() {
	fmt.Println("Hello, World!")

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

	select {}
}
