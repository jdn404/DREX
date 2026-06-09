package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

func validateSNIBug(ip, host string, timeout time.Duration) bool {
	tlsConf := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", ip+":443", tlsConf)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	req := "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\nUser-Agent: Mozilla/5.0 (Linux; Android 13)\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return false
	}
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n < 12 {
		return false
	}
	resp := string(buf[:n])
	firstLine := strings.SplitN(resp, "\r\n", 2)[0]
	parts := strings.Fields(firstLine)
	if len(parts) < 2 {
		return false
	}
	code := parts[1]
	validCodes := map[string]bool{
		"200": true, "301": true, "302": true, "304": true,
		"307": true, "308": true, "400": true, "403": true, "404": true,
	}
	return validCodes[code]
}

func validateProxy(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write([]byte("CONNECT httpbin.org:443 HTTP/1.1\r\nHost: httpbin.org:443\r\nProxy-Connection: Keep-Alive\r\n\r\n"))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n < 12 {
		return false
	}
	return strings.Contains(string(buf[:n]), "200")
}
