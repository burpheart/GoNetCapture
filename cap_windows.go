//go:build windows
// +build windows

package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

var (
	ws2_32 = syscall.NewLazyDLL("wsock32.dll")
	recv   = ws2_32.NewProc("recv")
)

const (
	SIO_RCVALL     = syscall.IOC_IN | syscall.IOC_VENDOR | 1
	RCVALL_IPLEVEL = 3
)

func cappacp() {
	//var flagHEX bool
	IPADDR := flag.String("a", "127.0.0.1", "NIC IP Addr")
	filenmae := flag.String("f", "./cap.pcap", "pcap file save path")
	flagHEX := flag.Bool("x", false, "only print hex dump")

	flag.Parse()

	fmt.Printf("Start packet capture! NIC addr: %s  pcap save path: %s\n", *IPADDR, *filenmae)

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_IP) //创建一个 RAW SOCKET
	if err != nil {
		fmt.Println("Socket ERROR", err)
		return
	}
	defer syscall.Close(fd)
	ip := net.ParseIP(*IPADDR)

	var ipv4 [4]byte
	copy(ipv4[:], ip.To4())
	addr := syscall.SockaddrInet4{
		Port: 0,
		Addr: ipv4,
	}

	err = syscall.Bind(fd, &addr)
	if err != nil {
		fmt.Println(err)
		return
	}

	flags := uint32(RCVALL_IPLEVEL)
	size := uint32(unsafe.Sizeof(flags))
	unused := uint32(0)
	err = syscall.WSAIoctl(fd, SIO_RCVALL, (*byte)(unsafe.Pointer(&flags)), size, nil, 0, &unused, nil, 0) //设置 SIO_RCVALL
	if err != nil {
		fmt.Println("WSAIoctl ERROR", err)
		return
	}
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
	err = w.WriteFileHeader(1024, layers.LinkTypeEthernet)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()
	buf := make([]byte, 65536)
	for {

		n, _, err := recv.Call(uintptr(fd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(0)) //调用recv 获取数据包

		if err.Error() != "The operation completed successfully." {
			fmt.Println("Recvfrom ERROR", err)
		}
		if *flagHEX {
			fmt.Println(hex.Dump(buf[:n]))
		} else {
			go func() {
				var c gopacket.CaptureInfo
				c.Timestamp = time.Now()
				c.InterfaceIndex = 0
				c.Length = int(n) + 14
				c.CaptureLength = int(n) + 14
				var buffer bytes.Buffer
				buffer.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0}) //固定一个假的ETH头
				buffer.Write(buf[:n])
				err = w.WritePacket(c, buffer.Bytes())
				if err != nil {
					fmt.Println("WritePacket ERROR", err)
				}
			}()
		}

	}
}
