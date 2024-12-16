package main

// ignore this file for now.

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	totp_manager "github.com/RU4DH4N/thered/util"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type KnockAttempt struct {
	firstKnock    time.Time
	knockSequence []uint16
}

var currentAttempts sync.Map

func removeInvalidAttempts() {
	currentAttempts.Range(func(key, value interface{}) bool {
		addr := key.(net.IP)
		attempt := value.(KnockAttempt)

		rounded := attempt.firstKnock.Truncate(30 * time.Second)
		if time.Since(rounded) >= 30*time.Second {
			fmt.Println("Removing", addr)
			currentAttempts.Delete(addr)
		}
		return true // Continue iteration
	})
}

func addAttempt(sender net.IP, attempt KnockAttempt) {
	currentAttempts.Store(sender, attempt)
}

func GetDefaultInterfaceName() (string, error) {
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
	var srcIP gopacket.Endpoint
	var port uint16
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		srcIP, _ = netLayer.NetworkFlow().Endpoints()
	}

	if transLayer := packet.TransportLayer(); transLayer != nil {
		if udp, ok := transLayer.(*layers.UDP); ok {
			port = uint16(udp.DstPort)
		} else {
			return // only udp packets
		}
	}

	senderIP := net.IP(srcIP.Raw())

	// this isn't going to work (it's making a copy which I need to set back.)
	if x, found := currentAttempts.Load(senderIP); found {
		attempt, ok := x.(KnockAttempt)

		if !ok {
			return
		}

		attempt.knockSequence = append(attempt.knockSequence, port)

		// this is temporary
		if isValid, err := totp_manager.CheckSequence(attempt.knockSequence); !isValid || err != nil {
			log.Println(err)
			return
		}

		// We can assume that the sequence is valid at this point...
		// need to somehow check if the sequence is complete (sequence + port to open)
		// maybe CheckSequence should return (bool, bool, error) with the second bool being isComplete?
	}
}
