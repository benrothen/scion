// Copyright 2020 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package slayers_test

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	rawUDPPktFilename  = "scion-udp.bin"
	rawFullPktFilename = "scion-udp-extn.bin"
)

// TODO(shitz): Ideally, these would be table-driven tests.

func TestDecodeSCIONUDP(t *testing.T) {
	raw := xtest.MustReadFromFile(t, rawUDPPktFilename)

	packet := gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.Default)
	assert.Nil(t, packet.ErrorLayer(), "Packet parsing should not error")

	// Check that there are exactly 3 layers (SCION, SCION/UDP, Payload)
	assert.Equal(t, 3, len(packet.Layers()), "Packet must have 3 layers")

	scnL := packet.Layer(slayers.LayerTypeSCION)
	require.NotNil(t, scnL, "SCION layer should exist")
	s := scnL.(*slayers.SCION) // Guaranteed to work
	// Check SCION Header
	assert.Equal(t, uint8(29), s.HdrLen, "HdrLen")
	assert.Equal(t, uint16(1032), s.PayloadLen, "PayloadLen")
	assert.Equal(t, common.L4UDP, s.NextHdr, "CmnHdr.NextHdr")

	// Check SCION/UDP Header
	udpL := packet.Layer(slayers.LayerTypeSCIONUDP)
	require.NotNil(t, udpL, "SCION/UDP layer should exist")
	udpHdr := udpL.(*slayers.UDP) // Guaranteed to work

	assert.Equal(t, layers.UDPPort(1280), udpHdr.SrcPort, "UDP.SrcPort")
	assert.Equal(t, layers.UDPPort(80), udpHdr.DstPort, "UDP.DstPort")
	assert.Equal(t, uint16(1032), udpHdr.Length, "UDP.Len")
	assert.Equal(t, uint16(0xbbda), udpHdr.Checksum, "UDP.Checksum")

	// Check Payload
	appLayer := packet.ApplicationLayer()
	require.NotNil(t, appLayer, "Application Layer should exist")
	assert.Equal(t, mkPayload(1024), appLayer.Payload(), "Payload")

}

func TestSerializeSCIONUPDExtn(t *testing.T) {
	s := prepPacket(t)
	s.NextHdr = common.HopByHopClass
	u := &slayers.UDP{}
	u.SrcPort = layers.UDPPort(1280)
	u.DstPort = layers.UDPPort(80)
	u.SetNetworkLayerForChecksum(s)
	hbh := &slayers.HopByHopExtn{}
	hbh.NextHdr = common.End2EndClass
	hbh.Options = []*slayers.HopByHopOption{
		(*slayers.HopByHopOption)(&optX),
		(*slayers.HopByHopOption)(&optY),
	}
	e2e := &slayers.EndToEndExtn{}
	e2e.NextHdr = common.L4UDP
	e2e.Options = []*slayers.EndToEndOption{
		(*slayers.EndToEndOption)(&optY),
		(*slayers.EndToEndOption)(&optX),
	}
	pld := gopacket.Payload(mkPayload(1024))
	b := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	assert.NoError(t, gopacket.SerializeLayers(b, opts, s, hbh, e2e, u, pld), "Serialize")
	raw := xtest.MustReadFromFile(t, rawFullPktFilename)
	assert.Equal(t, raw, b.Bytes(), "Raw buffer")
}

func TestDecodeSCIONUDPExtn(t *testing.T) {
	raw := xtest.MustReadFromFile(t, rawFullPktFilename)
	packet := gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.Default)
	assert.Nil(t, packet.ErrorLayer(), "Packet parsing should not error")
	// Check that there are exactly 5 layers (SCION, HBH, E2E, SCION/UDP, Payload)
	assert.Equal(t, 5, len(packet.Layers()), "Packet must have 5 layers")

	scnL := packet.Layer(slayers.LayerTypeSCION)
	require.NotNil(t, scnL, "SCION layer should exist")
	s := scnL.(*slayers.SCION) // Guaranteed to work
	// Check SCION Header
	assert.Equal(t, uint8(29), s.HdrLen, "HdrLen")
	assert.Equal(t, uint16(1092), s.PayloadLen, "PayloadLen")
	assert.Equal(t, common.HopByHopClass, s.NextHdr, "scion.NextHdr")

	// Check H2H Extn
	hbhL := packet.Layer(slayers.LayerTypeHopByHopExtn)
	require.NotNil(t, hbhL, "HBH layer should exist")
	hbh := hbhL.(*slayers.HopByHopExtn) // Guaranteed to work
	assert.Equal(t, common.End2EndClass, hbh.NextHdr, "NextHeader")
	assert.Equal(t, uint8(6), hbh.ExtLen, "HBH ExtLen")
	assert.Equal(t, 3, len(hbh.Options), "len(hbh.Options)")
	assert.Equal(t, 28, hbh.ActualLen, "ActualLength")

	// Check E2E Extn
	e2eL := packet.Layer(slayers.LayerTypeEndToEndExtn)
	require.NotNil(t, hbhL, "E2E layer should exist")
	e2e := e2eL.(*slayers.EndToEndExtn) // Guaranteed to work
	assert.Equal(t, common.L4UDP, e2e.NextHdr, "NextHeader")
	assert.Equal(t, uint8(7), e2e.ExtLen, "E2E ExtLen")
	assert.Equal(t, 4, len(e2e.Options), "len(hbh.Options)")
	assert.Equal(t, 32, e2e.ActualLen, "ActualLength")

	// Check SCION/UDP Header
	udpL := packet.Layer(slayers.LayerTypeSCIONUDP)
	require.NotNil(t, udpL, "SCION/UDP layer should exist")
	udpHdr := udpL.(*slayers.UDP) // Guaranteed to work
	assert.Equal(t, layers.UDPPort(1280), udpHdr.SrcPort, "UDP.SrcPort")
	assert.Equal(t, layers.UDPPort(80), udpHdr.DstPort, "UDP.DstPort")
	assert.Equal(t, uint16(1032), udpHdr.Length, "UDP.Len")
	assert.Equal(t, uint16(0xbbda), udpHdr.Checksum, "UDP.Checksum")

	// Check Payload
	appLayer := packet.ApplicationLayer()
	require.NotNil(t, appLayer, "Application Layer should exist")
	assert.Equal(t, mkPayload(1024), appLayer.Payload(), "Payload")
}

func TestPacketDecodeIsInverseOfSerialize(t *testing.T) {
	raw := xtest.MustReadFromFile(t, rawFullPktFilename)
	packet := gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.Default)
	require.Nil(t, packet.ErrorLayer(), "Packet parsing should not error")

	scnL := packet.Layer(slayers.LayerTypeSCION)
	require.NotNil(t, scnL, "SCION layer should exist")
	s := scnL.(*slayers.SCION) // Guaranteed to work
	hbhL := packet.Layer(slayers.LayerTypeHopByHopExtn)
	require.NotNil(t, hbhL, "HBH layer should exist")
	hbh := hbhL.(*slayers.HopByHopExtn) // Guaranteed to work
	e2eL := packet.Layer(slayers.LayerTypeEndToEndExtn)
	require.NotNil(t, hbhL, "E2E layer should exist")
	e2e := e2eL.(*slayers.EndToEndExtn) // Guaranteed to work
	udpL := packet.Layer(slayers.LayerTypeSCIONUDP)
	require.NotNil(t, udpL, "SCION/UDP layer should exist")
	udpHdr := udpL.(*slayers.UDP) // Guaranteed to work
	appLayer := packet.ApplicationLayer()
	require.NotNil(t, appLayer, "Application Layer should exist")

	b := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	require.NoError(t, gopacket.SerializeLayers(b, opts, s, hbh, e2e, udpHdr,
		gopacket.Payload(appLayer.Payload())), "Serialize")

	assert.Equal(t, raw, b.Bytes())
}

func BenchmarkDecodeEager(b *testing.B) {
	raw := xtest.MustReadFromFile(b, rawUDPPktFilename)

	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.Default)
	}
}

func BenchmarkDecodeLayerParser(b *testing.B) {
	raw := xtest.MustReadFromFile(b, rawUDPPktFilename)
	var scn slayers.SCION
	var hbh slayers.HopByHopExtn
	var e2e slayers.EndToEndExtn
	var udp slayers.UDP
	var scmp slayers.SCMP
	parser := gopacket.NewDecodingLayerParser(slayers.LayerTypeSCION, &scn, &hbh, &e2e, &udp, &scmp)
	decoded := []gopacket.LayerType{}
	for i := 0; i < b.N; i++ {
		parser.DecodeLayers(raw, &decoded)
	}
}

func BenchmarkDecodeLayerParserExtn(b *testing.B) {
	raw := xtest.MustReadFromFile(b, rawFullPktFilename)
	var scn slayers.SCION
	var hbh slayers.HopByHopExtn
	var e2e slayers.EndToEndExtn
	var udp slayers.UDP
	var scmp slayers.SCMP
	parser := gopacket.NewDecodingLayerParser(slayers.LayerTypeSCION, &scn, &hbh, &e2e, &udp, &scmp)
	decoded := []gopacket.LayerType{}
	for i := 0; i < b.N; i++ {
		parser.DecodeLayers(raw, &decoded)
	}
}

func mkPayload(plen int) []byte {
	b := make([]byte, plen)
	for i := 0; i < plen; i++ {
		b[i] = uint8(i % 256)
	}
	return b
}
