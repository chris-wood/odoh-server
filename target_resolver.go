package main

import (
	"fmt"
	"github.com/chris-wood/dns"
	"net"
	"time"
)

type targetResolver struct {
	nameserver string
	timeout    time.Duration
}

func (s targetResolver) resolve(query *dns.Msg) (*dns.Msg, error) {
	connection := new(dns.Conn)
	var err error
	if connection.Conn, err = net.DialTimeout("tcp", s.nameserver, s.timeout*time.Millisecond); err != nil {
		return nil, fmt.Errorf("Failed starting resolver connection")
	}

	connection.SetReadDeadline(time.Now().Add(s.timeout * time.Millisecond))
	connection.SetWriteDeadline(time.Now().Add(s.timeout * time.Millisecond))

	if err := connection.WriteMsg(query); err != nil {
		return nil, err
	}

	response, err := connection.ReadMsg()
	if err != nil {
		return nil, err
	}

	response.Id = query.Id
	return response, nil
}
