// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2021 ETH Zurich

// NOTE: Most of this code is just copied from scion-time
// It however does not use the SHA1-CBC-MAC that lightning filter uses.
// It uses CMAC without hashing. It is therefore not really usefull yet.

package main

import (
	"C"

	"github.com/google/gopacket"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/spao"
)
import (
	"encoding/binary"
	"net"
	"net/netip"
	"unsafe"
)

const (
	EndhostPort = 30041
	MTU         = 9216 - 20 - 8
)

const (
	drkeyTypeHostHost          = 1
	drkeyDirectionSenderSide   = 0
	drkeyDirectionReceiverSide = 1
	DRKeyProtocolTS            = 123

	PacketAuthMetadataLen = 12
	PacketAuthMACLen      = 16
	PacketAuthOptDataLen  = PacketAuthMetadataLen + PacketAuthMACLen

	PacketAuthSPIClient = uint32(drkeyTypeHostHost)<<17 |
		uint32(drkeyDirectionReceiverSide)<<16 |
		uint32(DRKeyProtocolTS)
	PacketAuthSPIServer = uint32(drkeyTypeHostHost)<<17 |
		uint32(drkeyDirectionSenderSide)<<16 |
		uint32(DRKeyProtocolTS)
	PacketAuthAlgorithm = uint8(0) // AES-CMAC
)

type UDPAddr struct {
	IA   addr.IA
	Host *net.UDPAddr
}

func PreparePacketAuthOpt(authOpt *slayers.EndToEndOption, spi uint32, algo uint8) {
	authOptData := authOpt.OptData
	authOptData[0] = byte(spi >> 24)
	authOptData[1] = byte(spi >> 16)
	authOptData[2] = byte(spi >> 8)
	authOptData[3] = byte(spi)
	authOptData[4] = byte(algo)
	// TODO: Timestamp and Sequence Number
	// See https://github.com/scionproto/scion/pull/4300
	authOptData[5], authOptData[6], authOptData[7] = 0, 0, 0
	authOptData[8], authOptData[9], authOptData[10], authOptData[11] = 0, 0, 0, 0
	// Authenticator
	authOptData[12], authOptData[13], authOptData[14], authOptData[15] = 0, 0, 0, 0
	authOptData[16], authOptData[17], authOptData[18], authOptData[19] = 0, 0, 0, 0
	authOptData[20], authOptData[21], authOptData[22], authOptData[23] = 0, 0, 0, 0
	authOptData[24], authOptData[25], authOptData[26], authOptData[27] = 0, 0, 0, 0

	authOpt.OptType = slayers.OptTypeAuthenticator
	authOpt.OptData = authOptData
	authOpt.OptAlign[0] = 4
	authOpt.OptAlign[1] = 2
	authOpt.OptDataLen = 0
	authOpt.ActualLength = 0
}

func PacketAuthOptMAC(authOpt *slayers.EndToEndOption) []byte {
	authOptData := authOpt.OptData
	if len(authOptData) != PacketAuthOptDataLen {
		panic("unexpected authenticator option data")
	}
	return authOptData[PacketAuthMetadataLen:]
}

func UDPAddrFromSnet(a *snet.UDPAddr) UDPAddr {
	return UDPAddr{a.IA, snet.CopyUDPAddr(a.Host)}
}

//export CreateSpaoPacket
func CreateSpaoPacket(test_int uint64, keyPtr unsafe.Pointer, pktBuffer unsafe.Pointer) int {

	authKey := make([]byte, 16)
	copy(authKey[:], (*[16]byte)(keyPtr)[:])

	var remoteAddrSCION snet.UDPAddr
	err := remoteAddrSCION.Set("1-ff00:0:112,10.1.1.12")
	if err != nil {
		return 1
	}

	var localAddrSCION snet.UDPAddr
	err = localAddrSCION.Set("1-ff00:0:112,10.1.1.11")
	if err != nil {
		return 1
	}

	var remoteAddr UDPAddr = UDPAddrFromSnet(&remoteAddrSCION)
	var localAddr UDPAddr = UDPAddrFromSnet(&localAddrSCION)

	buf := make([]byte, MTU)
	binary.BigEndian.PutUint64(buf[0:], 0xFFFFFFFFFFFFFFFF)

	var scionLayer slayers.SCION
	scionLayer.TrafficClass = 0
	scionLayer.SrcIA = localAddr.IA
	srcAddrIP, ok := netip.AddrFromSlice(localAddr.Host.IP)
	if !ok {
		return 1
	}
	err = scionLayer.SetSrcAddr(addr.HostIP(srcAddrIP.Unmap()))
	if err != nil {
		return 1
	}
	scionLayer.DstIA = remoteAddr.IA
	dstAddrIP, ok := netip.AddrFromSlice(remoteAddr.Host.IP)
	if !ok {
		return 1
	}
	err = scionLayer.SetDstAddr(addr.HostIP(dstAddrIP.Unmap()))
	if err != nil {
		return 1
	}

	scionLayer.Path = empty.Path{}
	scionLayer.PathType = empty.PathType

	scionLayer.NextHdr = slayers.L4UDP

	var localPort int = 0xF0F0
	var destinationPort int = 0xF0F0
	var udpLayer slayers.UDP
	udpLayer.SrcPort = uint16(localPort)
	udpLayer.DstPort = uint16(destinationPort)
	udpLayer.SetNetworkLayerForChecksum(&scionLayer)

	payload := gopacket.Payload(buf)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err = payload.SerializeTo(buffer, options)
	if err != nil {
		return 1
	}
	buffer.PushLayer(payload.LayerType())

	err = udpLayer.SerializeTo(buffer, options)
	if err != nil {
		return 1
	}
	buffer.PushLayer(udpLayer.LayerType())

	auth := &slayers.EndToEndOption{}
	auth.OptData = make([]byte, PacketAuthOptDataLen)
	authBuff := make([]byte, spao.MACBufferSize)

	PreparePacketAuthOpt(auth, PacketAuthSPIClient, PacketAuthAlgorithm)
	_, err = spao.ComputeAuthCMAC(
		spao.MACInput{
			Key:        authKey,
			Header:     slayers.PacketAuthOption{EndToEndOption: auth},
			ScionLayer: &scionLayer,
			PldType:    scionLayer.NextHdr,
			Pld:        buffer.Bytes(),
		},
		authBuff,
		PacketAuthOptMAC(auth),
	)
	if err != nil {
		return 1
	}

	e2eExtn := slayers.EndToEndExtn{}
	e2eExtn.NextHdr = scionLayer.NextHdr
	e2eExtn.Options = []*slayers.EndToEndOption{auth}

	err = e2eExtn.SerializeTo(buffer, options)
	if err != nil {
		return 1
	}
	buffer.PushLayer(e2eExtn.LayerType())

	scionLayer.NextHdr = slayers.End2EndClass

	err = scionLayer.SerializeTo(buffer, options)
	if err != nil {
		return 1
	}
	buffer.PushLayer(scionLayer.LayerType())

	copy((*[128]byte)(pktBuffer)[:], buffer.Bytes()[:])

	return 0
}

func main() {}
