package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"reflect"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	totp_manager "github.com/RU4DH4N/thered/util"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	memoryLimit = 50 // limit in MiB
)

type KnockAttempt struct {
	firstKnock    time.Time
	knockSequence []uint16
}

var currentAttempts sync.Map

func RemoveInvalidAttempts() {
	currentAttempts.Range(func(key, value interface{}) bool {
		attempt := value.(KnockAttempt)

		rounded := attempt.firstKnock.Truncate(totp_manager.SequenceInterval)
		if time.Since(rounded) >= totp_manager.SequenceInterval {
			currentAttempts.Delete(key)
		}
		return true
	})
}

func GetDefaultInterfaceName() (string, error) {

	// Definitely a better way to do this.
	cmd := exec.Command("sh", "-c", "ip route | grep default | awk '{print $5}' | head -n 1")
	output, err := cmd.Output()

	if err != nil {
		return "", fmt.Errorf("failed to execute command to get interface name: %v", err)
	}

	interfaceName := strings.TrimSpace(string(output))
	if interfaceName == "" {
		return "", fmt.Errorf("couldn't find default interface name")
	}

	return interfaceName, nil
}

func main() {
	debug.SetMemoryLimit(memoryLimit * 1024 * 1024)

	// this probably isn't necessary
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func(ctx context.Context) {
		ticker := time.NewTicker(totp_manager.SequenceInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				RemoveInvalidAttempts()
			case <-ctx.Done():
				return
			}
		}
	}(ctx)

	interfaceName, err := GetDefaultInterfaceName()

	if err != nil {
		log.Fatalf("failed to get default interface: %v", err)
		return
	}

	handle, err := pcap.OpenLive(interfaceName, 1600, false, pcap.BlockForever)

	if err != nil {
		log.Fatalf("failed to open device %s: %v", interfaceName, err)
	}

	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		ProcessPacket(packet)
	}
}

func ProcessPacket(packet gopacket.Packet) {

	if packet == nil {
		return
	}

	var srcIP gopacket.Endpoint
	var port uint16
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		srcIP, _ = netLayer.NetworkFlow().Endpoints()
	} else {
		return
	}

	// need to filter packets here

	if transLayer := packet.TransportLayer(); transLayer != nil {
		if udp, ok := transLayer.(*layers.UDP); ok {
			port = uint16(udp.DstPort)
			if port == 0 {
				return
			}
		} else {
			return // only udp packets
		}
	} else {
		return
	}

	senderIP := net.IP(srcIP.Raw())

	if senderIP.IsUnspecified() {
		return
	}

	var key [16]byte
	copy(key[:], senderIP.To16())

	var currentAttempt KnockAttempt

	if x, found := currentAttempts.Load(key); found {
		if attempt, ok := x.(KnockAttempt); ok { // TEMPORARY
			currentAttempt = attempt
			currentAttempt.knockSequence = append(currentAttempt.knockSequence, port)
			fmt.Printf("current sequence from found %v\n", currentAttempt.knockSequence)

		} else {
			fmt.Printf("currentAttempt is not of type 'KnockAttempt', of type: %v", reflect.TypeOf(x))
			return
		}
	} else {
		currentAttempt = KnockAttempt{
			firstKnock:    time.Now(),
			knockSequence: []uint16{port},
		}
	}

	if isValid, err := totp_manager.CheckSequence(currentAttempt.knockSequence); !isValid || err != nil {
		fmt.Printf("deleting %v with sequence %v\n", senderIP, currentAttempt.knockSequence)

		if err != nil {
			fmt.Printf("error: %v", err)
		}

		currentAttempts.Delete(key)
		return
	}

	fmt.Printf("updating %v with sequence %v\n", key, currentAttempt.knockSequence)
	currentAttempts.Store(key, currentAttempt)
	// need to determine if sequence is complete and figure out which port needs to be opened
}
