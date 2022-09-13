package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/HyNetwork/hysteria/pkg/conns/faketcp"
	"github.com/HyNetwork/hysteria/pkg/conns/udp"
	"github.com/HyNetwork/hysteria/pkg/conns/wechat"
	obfsPkg "github.com/HyNetwork/hysteria/pkg/obfs"
	"github.com/lucas-clemente/quic-go"
)

type ClientTransport struct {
	Dialer            *net.Dialer
	ResolvePreference ResolvePreference
}

var DefaultClientTransport = &ClientTransport{
	Dialer: &net.Dialer{
		Timeout: 8 * time.Second,
	},
	ResolvePreference: ResolvePreferenceDefault,
}

func (ct *ClientTransport) quicPacketConn(proto string, server string, obfs obfsPkg.Obfuscator, dialer PacketDialer) (net.PacketConn, error) {
	if len(proto) == 0 || proto == "udp" {
		conn, err := dialer.ListenPacket()
		if err != nil {
			return nil, err
		}
		if obfs != nil {
			oc := udp.NewObfsUDPConn(conn, obfs)
			return oc, nil
		} else {
			return conn, nil
		}
	} else if proto == "wechat-video" {
		conn, err := dialer.ListenPacket()
		if err != nil {
			return nil, err
		}
		if obfs == nil {
			obfs = obfsPkg.NewDummyObfuscator()
		}
		return wechat.NewObfsWeChatUDPConn(conn, obfs), nil
	} else if proto == "faketcp" {
		var conn *faketcp.TCPConn
		conn, err := faketcp.Dial("tcp", server)
		if err != nil {
			return nil, err
		}
		if obfs != nil {
			oc := faketcp.NewObfsFakeTCPConn(conn, obfs)
			return oc, nil
		} else {
			return conn, nil
		}
	} else {
		return nil, fmt.Errorf("unsupported protocol: %s", proto)
	}
}

type PacketDialer interface {
	ListenPacket() (net.PacketConn, error)
	Context() context.Context
}

type defaultPacketDialer struct{}

func (dialer *defaultPacketDialer) ListenPacket() (net.PacketConn, error) {
	return net.ListenUDP("udp", nil)
}

func (dialer *defaultPacketDialer) Context() context.Context {
	return context.Background()
}

func (ct *ClientTransport) QUICDial(proto string, server string, tlsConfig *tls.Config, quicConfig *quic.Config, obfs obfsPkg.Obfuscator, dialer PacketDialer) (quic.Connection, error) {
	if dialer == nil {
		dialer = &defaultPacketDialer{}
	}

	serverUDPAddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, err
	}
	pktConn, err := ct.quicPacketConn(proto, server, obfs, dialer)
	if err != nil {
		return nil, err
	}
	qs, err := quic.DialContext(dialer.Context(), pktConn, serverUDPAddr, server, tlsConfig, quicConfig)
	if err != nil {
		_ = pktConn.Close()
		return nil, err
	}
	return qs, nil
}

func (ct *ClientTransport) ResolveIPAddr(address string) (*net.IPAddr, error) {
	return resolveIPAddrWithPreference(address, ct.ResolvePreference)
}

func (ct *ClientTransport) DialTCP(raddr *net.TCPAddr) (*net.TCPConn, error) {
	conn, err := ct.Dialer.Dial("tcp", raddr.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}

func (ct *ClientTransport) ListenUDP() (*net.UDPConn, error) {
	return net.ListenUDP("udp", nil)
}
