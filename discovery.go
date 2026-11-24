package main

import (
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"strings"
	"unicode"
)

const discoveryPort = 38738

type discoveryQuery struct {
	Protocol string `json:"protocol"`
	Nonce    string `json:"nonce"`
}

type discoveryReply struct {
	Protocol string `json:"protocol"`
	Nonce    string `json:"nonce"`
	Invite   string `json:"invite"`
	Name     string `json:"name"`
}

func lanName() string {
	name, err := os.Hostname()
	if err == nil && strings.TrimSpace(name) != "" && len(name) <= 120 &&
		strings.IndexFunc(name, unicode.IsControl) == -1 {
		return name
	}
	return "YAP Sync"
}

func listenDiscovery(ip netip.Addr, name, invite string) (*net.UDPConn, error) {
	ip = ip.Unmap()
	if !ip.Is4() || ip.IsLoopback() {
		return nil, nil
	}
	var subnet netip.Prefix
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, address := range addresses {
		if prefix, err := netip.ParsePrefix(address.String()); err == nil && prefix.Addr() == ip {
			subnet = prefix.Masked()
			break
		}
	}
	if !subnet.IsValid() {
		return nil, nil
	}
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: discoveryPort})
	if err != nil {
		return nil, err
	}
	// A separate socket selects the advertised adapter for replies.
	outgoing, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(ip.AsSlice())})
	if err != nil {
		listener.Close()
		return nil, err
	}
	go func() {
		defer outgoing.Close()
		buffer := make([]byte, 256)
		for {
			size, source, err := listener.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			if !subnet.Contains(source.Addr().Unmap()) {
				continue
			}
			if reply, ok := discoveryResponse(buffer[:size], name, invite); ok {
				outgoing.WriteToUDPAddrPort(reply, source)
			}
		}
	}()
	return listener, nil
}

func discoveryResponse(query []byte, name, invite string) ([]byte, bool) {
	var request discoveryQuery
	if json.Unmarshal(query, &request) != nil || request.Protocol != "yap-sync-discovery/1" || !validHex(request.Nonce, 32) {
		return nil, false
	}
	reply, err := json.Marshal(discoveryReply{
		Protocol: request.Protocol, Nonce: request.Nonce, Invite: invite, Name: name,
	})
	return reply, err == nil && len(reply) <= 4096
}
