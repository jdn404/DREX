package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

type Hit struct {
	IP       string    `json:"ip"`
	Port     int       `json:"port"`
	Type     string    `json:"type"`
	Host     string    `json:"host,omitempty"`
	Latency  int64     `json:"latency_ms"`
	Response string    `json:"response,omitempty"`
	Verified bool      `json:"verified"`
	Time     time.Time `json:"found_at"`
}

func probeHTTPProxy(ip string, port int, timeout time.Duration) *Hit {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write([]byte("CONNECT httpbin.org:443 HTTP/1.1\r\nHost: httpbin.org:443\r\nProxy-Connection: Keep-Alive\r\n\r\n"))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return nil
	}
	resp := string(buf[:n])
	if !strings.Contains(resp, "200") {
		return nil
	}
	return &Hit{
		IP: ip, Port: port, Type: "HTTP_PROXY",
		Latency:  time.Since(start).Milliseconds(),
		Response: strings.SplitN(resp, "\r\n", 2)[0],
		Time:     time.Now(),
	}
}

func probeHTTPSProxy(ip string, port int, timeout time.Duration) *Hit {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write([]byte("CONNECT google.com:443 HTTP/1.1\r\nHost: google.com:443\r\n\r\n"))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n < 12 {
		return nil
	}
	resp := string(buf[:n])
	if !strings.Contains(resp, "200") {
		return nil
	}
	return &Hit{
		IP: ip, Port: port, Type: "HTTPS_PROXY",
		Latency:  time.Since(start).Milliseconds(),
		Response: strings.SplitN(resp, "\r\n", 2)[0],
		Time:     time.Now(),
	}
}

func probeSOCKS5(ip string, port int, timeout time.Duration) *Hit {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 2)
	n, _ := conn.Read(buf)
	if n < 2 || buf[0] != 0x05 || buf[1] != 0x00 {
		return nil
	}
	return &Hit{
		IP: ip, Port: port, Type: "SOCKS5",
		Latency: time.Since(start).Milliseconds(),
		Time:    time.Now(),
	}
}

func probeSNI(ip, host string, timeout time.Duration) *Hit {
	start := time.Now()
	tlsConf := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", ip+":443", tlsConf)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write([]byte("HEAD / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n < 12 {
		return nil
	}
	resp := string(buf[:n])
	firstLine := strings.SplitN(resp, "\r\n", 2)[0]
	if !strings.HasPrefix(firstLine, "HTTP/") {
		return nil
	}
	parts := strings.Fields(firstLine)
	if len(parts) < 2 {
		return nil
	}
	code := parts[1]
	validCodes := map[string]bool{
		"200": true, "301": true, "302": true, "304": true,
		"307": true, "308": true, "403": true, "404": true, "405": true,
	}
	if !validCodes[code] {
		return nil
	}
	return &Hit{
		IP: ip, Port: 443, Type: "SNI_BUG",
		Host:     host,
		Latency:  time.Since(start).Milliseconds(),
		Response: firstLine,
		Time:     time.Now(),
	}
}

func probeHTTPInject(ip string, port int, host string, payload PayloadTemplate, timeout time.Duration) *Hit {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	req := strings.ReplaceAll(payload.Template, "{h}", host)
	conn.Write([]byte(req))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n < 12 {
		return nil
	}
	resp := string(buf[:n])
	firstLine := strings.SplitN(resp, "\r\n", 2)[0]
	if !strings.HasPrefix(firstLine, "HTTP/") {
		return nil
	}
	parts := strings.Fields(firstLine)
	if len(parts) < 2 {
		return nil
	}
	code := parts[1]
	if code == "000" || code == "503" {
		return nil
	}
	return &Hit{
		IP: ip, Port: port, Type: "HTTP_INJECT_" + strings.ToUpper(payload.Name),
		Host:     host,
		Latency:  time.Since(start).Milliseconds(),
		Response: firstLine,
		Time:     time.Now(),
	}
}

func probeWebSocket(ip string, port int, host string, timeout time.Duration) *Hit {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	req := "GET / HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	conn.Write([]byte(req))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n < 12 {
		return nil
	}
	resp := string(buf[:n])
	if !strings.Contains(resp, "101") && !strings.Contains(strings.ToLower(resp), "websocket") {
		return nil
	}
	return &Hit{
		IP: ip, Port: port, Type: "WEBSOCKET",
		Host:     host,
		Latency:  time.Since(start).Milliseconds(),
		Response: strings.SplitN(resp, "\r\n", 2)[0],
		Time:     time.Now(),
	}
}
