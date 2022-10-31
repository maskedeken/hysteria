package transport

import (
	"context"
	"net"
	"time"
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

type PacketDialer interface {
	ListenPacket() (net.PacketConn, error)
	Context() context.Context
}

type DefaultPacketDialer struct{}

func (dialer *DefaultPacketDialer) ListenPacket() (net.PacketConn, error) {
	return net.ListenUDP("udp", nil)
}

func (dialer *DefaultPacketDialer) Context() context.Context {
	return context.Background()
}
