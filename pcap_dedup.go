/*
 * Copyright (c) 2019, University Corporation for Atmospheric Research
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package main

import (
	"fmt"
	"log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"encoding/hex"
	"os"
	"bytes"
)

func main() {
	var last gopacket.Packet
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
		if (last == nil) {
			last = p
			continue
		}
		//log.Printf("%d\n", len(p.Data()))
		//ignore mac addresses
		if(bytes.Equal(p.Data()[12:], last.Data()[12:])) {
			count++
			if(count == 2) {
				opcap.WritePacket(last.Metadata().CaptureInfo, last.Data())
			}
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
		last = p
		if(debug == true) {
			fmt.Println(hex.EncodeToString(p.Data()[12:]))
		}
		//fmt.Println("\n\n")
	}
}
