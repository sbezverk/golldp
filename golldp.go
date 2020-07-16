package main

import (
	"encoding/binary"
	"flag"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/raw"
	"github.com/sbezverk/gobmp/pkg/tools"
	"golang.org/x/net/bpf"
)

var port string

func init() {
	flag.StringVar(&port, "port", "eth0", "interface name to listen for lldp packet")
}

// LLDPtlv defines interface to manage LLDP packet's TLV
type LLDPtlv interface {
	MarshalBinary() []byte
	UnmarshalBinary([]byte) error
}

// LLDPpacket defines interface to manage information found in LLDP Frame
type LLDPpacket interface {
	GetNeighborID() []byte
	GetTLV() []TLV
	GetEtherType() uint16
}

// TLV defines LLDP tlv structure
type TLV struct {
	t uint8
	l uint16
	v []byte
}

// MarshalBinary serializes TLV into a []byte
func (t *TLV) MarshalBinary() []byte {
	return nil
}

// UnmarshalBinary instantiates new tlv from []byte
func (t *TLV) UnmarshalBinary(b []byte) error {
	return nil
}

var _ LLDPpacket = &lldpPacket{}

type lldpPacket struct {
	frame *ethernet.Frame
}

func (p *lldpPacket) GetNeighborID() []byte {
	return p.frame.Source
}

func (p *lldpPacket) GetEtherType() uint16 {
	return uint16(p.frame.EtherType)
}

func (p *lldpPacket) GetTLV() []TLV {
	tlvs := make([]TLV, 0)
	for i := 0; i < len(p.frame.Payload); {
		tlv := TLV{}
		t := p.frame.Payload[i]
		tlv.t = (uint8(t) >> 1)
		l := uint16(p.frame.Payload[i]&0x1) << 8
		if i+1 >= len(p.frame.Payload) {
			break
		}
		i++
		l += uint16(p.frame.Payload[i])
		tlv.l = l
		if tlv.t == 0 && tlv.l == 0 {
			// Found end of LLDP data
			tlvs = append(tlvs, tlv)
			break
		}
		if i+1 >= len(p.frame.Payload) {
			break
		}
		i++
		if i+int(l) >= len(p.frame.Payload) {
			break
		}
		tlv.v = make([]byte, l)
		copy(tlv.v, p.frame.Payload[i:i+int(l)])
		tlvs = append(tlvs, tlv)
		i += int(l)
	}

	return tlvs
}

// NewLLDPpacket returns LLDP packet interface to access information inside of LLDP packet
func NewLLDPpacket(b []byte) (LLDPpacket, error) {
	f := &ethernet.Frame{}
	if err := f.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	p := &lldpPacket{
		frame: f,
	}

	return p, nil
}

func main() {
	flag.Parse()
	_ = flag.Set("logtostderr", "true")

	l, err := net.InterfaceByName(port)
	if err != nil {
		glog.Errorf("failed to get interface %s information with error: %+v", port, err)
		os.Exit(1)
	}

	c, err := raw.ListenPacket(l, syscall.ETH_P_ALL, &raw.Config{})
	if err != nil {
		glog.Errorf("failed to listen for lldp connection with error: %+v", err)
		os.Exit(1)
	}
	defer c.Close()
	glog.Infof("Start listening on port: %s, local address: %s socket: %+v", port, c.LocalAddr().Network(), syscall.ETH_P_ALL)
//	filter, err := lldpFilter()
//	if err != nil {
//		glog.Errorf("failed to build bpf filter with error: %+v", err)
//		os.Exit(1)
//	}
//	glog.Infof("resulting bpf filter: %+v", filter)
//	if err := c.SetBPF(filter); err != nil {
//		glog.Errorf("failed to attach bpf filter with error: %+v", err)
//		os.Exit(1)
//	}
	if err := c.SetPromiscuous(true); err != nil {
		glog.Errorf("failed to set promiscuous mode with error: %+v", err)
		os.Exit(1)
	}
	if err := c.SetReadDeadline(time.Now().Add(time.Second * 120)); err != nil {
		glog.Errorf("failed to set Read Deadline timer with error: %+v", err)
		os.Exit(1)
	}
	// f := &ethernet.Frame{
	// 	Destination: []byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e},
	// 	EtherType:   0x88cc,
	// 	Payload:     []byte{},
	// }
	// b, err := f.MarshalBinary()
	// if err != nil {
	// 	glog.Errorf("failed to Marshal Ethernet Frame with error: %+v", err)
	// 	os.Exit(1)
	// }
	// c.WriteTo(b, &raw.Addr{HardwareAddr: []byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}})
	p := make([]byte, 9000)
	for {
		n, a, err := c.ReadFrom(p)
		if err != nil {
			glog.Errorf("failed to Receive LLDP frame with error: %+v", err)
			os.Exit(1)
		}
		glog.Infof("recevied lldp packet from: %s number of bytes: %d", a.String(), n)
		r, err := NewLLDPpacket(p[:n])
		if err != nil {
			glog.Errorf("failed to Unmarshal frame with error: %+v", err)
			os.Exit(1)
		}
		glog.Infof("Received packet of EtherType: 0x%04x", r.GetEtherType())
		if r.GetEtherType() == 0x88cc {
			glog.Infof("lldp packet from neighbor: %+v", r.GetNeighborID())

			tlvs := r.GetTLV()

			for _, tlv := range tlvs {
				switch tlv.t {
				case 0:
					glog.Infof("TLV type: %d, End of LLDP datagram", tlv.t)
				case 1:
					glog.Infof("TLV type: %d, Chassis type: %d id: %s", tlv.t, tlv.v[0], tools.MessageHex(tlv.v[1:]))
				case 2:
					glog.Infof("TLV type: %d, Port type: %d id: %s", tlv.t, tlv.v[0], tools.MessageHex(tlv.v[1:]))
				case 3:
					glog.Infof("TLV type: %d, Time to Live: %d", tlv.t, binary.BigEndian.Uint16(tlv.v))
				case 4:
					glog.Infof("TLV type: %d, Port description: %s", tlv.t, string(tlv.v))
				case 5:
					glog.Infof("TLV type: %d, System name: %s", tlv.t, string(tlv.v))
				case 6:
					glog.Infof("TLV type: %d, System description: %s", tlv.t, string(tlv.v))
				case 7:
					sc := parseLLDPcapabilities(tlv.v[:2])
					ec := parseLLDPcapabilities(tlv.v[2:])
					glog.Infof("TLV type: %d, System Capabilities: %s Enabled Capabilities: %s", tlv.t, strings.Join(sc, ", "), strings.Join(ec, ", "))
				case 8:
					al := tlv.v[0] - 1
					st := tlv.v[1]
					addr := make([]byte, al)
					copy(addr, tlv.v[2:2+al])
					var saddr string
					if al-1 == 4 {
						saddr = net.IP(addr).To4().String()
					} else {
						saddr = net.IP(addr).To16().String()
					}
					glog.Infof("TLV type: %d, Management address length: %d subtype: %d value: %s unknown: %s", tlv.t, al, st, saddr, tools.MessageHex(tlv.v[al+1:]))
				case 127:
					oui := tlv.v[0:3]
					st := tlv.v[3]
					glog.Infof("TLV type: %d, OUI: %02x-%02x-%02x Subtype: %d value: %s", tlv.t, oui[0], oui[1], oui[2], st, tools.MessageHex(tlv.v[4:]))
				default:
				}
			}
		}
	}
}

func parseLLDPcapabilities(b []byte) []string {
	caps := make([]string, 0)
	if len(b) != 2 {
		return nil
	}
	c := make([]byte, 2)
	c[0], c[1] = b[1], b[0]
	for n := range c {
		o := byte(1)
		for i := 0; i < 8; i++ {
			if c[n]&o != 0 {
				switch i + 1 + n*8 {
				case 1:
					caps = append(caps, "other")
				case 2:
					caps = append(caps, "repeater")
				case 3:
					caps = append(caps, "mac bridge component")
				case 4:
					caps = append(caps, "802.11 access point")
				case 5:
					caps = append(caps, "router")
				case 6:
					caps = append(caps, "telephone")
				case 7:
					caps = append(caps, "docsis cable device")
				case 8:
					caps = append(caps, "station only")
				case 9:
					caps = append(caps, "c-vlan component")
				case 10:
					caps = append(caps, "s-vlan component")
				case 11:
					caps = append(caps, "two-port mac relay component")
				}
			}
			o <<= 1
		}
	}
	return caps
}

const (
	etOff = 12
	etLen = 2

	etLLDP = 0x88cc
)

func lldpFilter() ([]bpf.RawInstruction, error) {
	return bpf.Assemble([]bpf.Instruction{
		// Load EtherType value from Ethernet header
		bpf.LoadAbsolute{
			Off:  etOff,
			Size: etLen,
		},
		// If EtherType is equal to the LLDP EtherType, jump to allow
		// packet to be accepted
		bpf.JumpIf{
			Cond:     bpf.JumpEqual,
			Val:      etLLDP,
			SkipTrue: 1,
		},
		// EtherType does not match the LLDP EtherType
		bpf.RetConstant{
			Val: 0,
		},
		// EtherType matches the LLDP EtherType, accept up to 9000
		// bytes of packet
		bpf.RetConstant{
			Val: 9000,
		},
	})
}
