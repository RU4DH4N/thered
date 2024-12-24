package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
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

var logger *slog.Logger

func main() {
	debug.SetMemoryLimit(memoryLimit * 1024 * 1024)

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Format timestamp as Linux logs do
			if a.Key == slog.TimeKey {
				a.Value = slog.StringValue(time.Now().Format("2006-01-02 15:04:05"))
			}
			// Use custom levels for severity
			if a.Key == slog.LevelKey {
				a.Value = slog.StringValue(a.Value.String())
			}
			return a
		},
	})

	logger = slog.New(handler)
	logger.Info("Logger Started")

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
		logger.Error("failed to get default interface", "error", err)
		os.Exit(1)
	}

	handle, err := pcap.OpenLive(interfaceName, 1600, false, pcap.BlockForever)

	if err != nil {
		logger.Error("failed to open device", "interface", interfaceName, "error", err)
		os.Exit(1)
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

			logger.Info("sequence found", "sequence", currentAttempt.knockSequence)
		} else {
			logger.Warn("currentAttempt not of type 'KnockAttempt', returning early", "type", reflect.TypeOf(x))
			return
		}
	} else {
		logger.Info("creating new knock attempt", "sequence", port)
		currentAttempt = KnockAttempt{
			firstKnock:    time.Now(),
			knockSequence: []uint16{port},
		}
	}

	if isValid, err := totp_manager.CheckSequence(currentAttempt.knockSequence); !isValid || err != nil {
		logger.Info("deleting KnockAttempt", "sender", senderIP, "sequence", currentAttempt.knockSequence)

		if err != nil {
			logger.Error("unable to check sequence, deleting knock attempt", "error", err)
		}

		currentAttempts.Delete(key)
		return
	}

	logger.Info("updating KnockAttempt", "sequence", currentAttempt.knockSequence)
	currentAttempts.Store(key, currentAttempt)
	// need to determine if sequence is complete and figure out which port needs to be opened
}
