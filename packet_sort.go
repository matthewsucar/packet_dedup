package main

import (
	"fmt"
	"log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	//"encoding/hex"
	"os"
	"bytes"
)

func main() {
	var last []byte
	count := 1
	debug := false

	handle, err := pcap.OpenOffline(os.Args[1])
	if err != nil { log.Fatal(err) }
	defer handle.Close()

	of, err := os.Create(os.Args[2])
	if err != nil { log.Fatal(err) }
	opcap := pcapgo.NewWriter(of)
	opcap.WriteFileHeader(9000, layers.LinkTypeEthernet)
	defer of.Close()

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	last = nil
	for p := range source.Packets() {
		if(bytes.Equal(p.Data(), last)) {
			count++
			opcap.WritePacket(p.Metadata().CaptureInfo, p.Data())
		} else {
			if (count > 1) {
				if(debug == true) {
					fmt.Printf("%d exact adjacent duplicates\n", count)
					//fmt.Println(p)
				}
			}
			count = 1
		}
		last = p.Data()
		//fmt.Println(hex.EncodeToString(p.Data()))
		//fmt.Println("\n\n")
	}
}
