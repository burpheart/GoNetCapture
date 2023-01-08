//go:build linux
// +build linux

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"os"
	"syscall"
	"time"
)

func Htons(v uint16) int {
	return int((v << 8) | (v >> 8))
}
func cappacp() {

	flagHEX := flag.Bool("x", false, "only print hex dump")
	filenmae := flag.String("f", "./cap.pcap", "pcap file save path")

	flag.Parse()

	// 打开raw socket
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, Htons(syscall.ETH_P_ALL))

	if err != nil {
		fmt.Println(err)
		return
	}
	defer syscall.Close(fd)
	buf := make([]byte, 65536)
	if _, err := os.Stat(*filenmae); !os.IsNotExist(err) {
		if err := os.Remove(*filenmae); err != nil {
			fmt.Println(err)
		}
	}

	f, err := os.OpenFile(*filenmae, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		fmt.Println(err)
		return
	}
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(1024, layers.LinkTypeEthernet)
	defer f.Close()

	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			fmt.Println("Recvfrom error", err)
			return
		}

		if *flagHEX {
			fmt.Println(hex.Dump(buf[:n]))
		} else {
			packet := buf[:n]
			var c gopacket.CaptureInfo
			c.InterfaceIndex = 0
			c.Length = n
			c.CaptureLength = n
			c.Timestamp = time.Now()
			err = w.WritePacket(c, packet)
			if err != nil {
				fmt.Println("WritePacket ERROR", err)
			}
		}

	}

}
