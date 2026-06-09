package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const exportDir = "drex_exports"

func ensureExportDir() {
	os.MkdirAll(exportDir, 0755)
}

func exportPath(name string) string {
	ts := time.Now().Format("20060102_150405")
	return filepath.Join(exportDir, fmt.Sprintf("%s_%s", name, ts))
}

func generateID(seed string) string {
	h := md5.Sum([]byte(seed))
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

func doExport(carrier Carrier, state *ScanState, format string) {
	ensureExportDir()
	proxies := state.getProxies()
	sniBugs := state.getSNIBugs()

	if len(proxies) == 0 && len(sniBugs) == 0 {
		cYellow.Println("  No results to export. Run a scan first.")
		return
	}

	var exported []string

	switch strings.ToLower(format) {
	case "hi":
		if f := exportHTTPInjector(carrier, proxies, sniBugs); f != "" {
			exported = append(exported, f)
		}
	case "v2ray":
		if f := exportV2Ray(carrier, sniBugs); f != "" {
			exported = append(exported, f)
		}
	case "napster":
		if f := exportNapsternetV(carrier, sniBugs); f != "" {
			exported = append(exported, f)
		}
	case "hc":
		if f := exportHTTPCustom(carrier, sniBugs); f != "" {
			exported = append(exported, f)
		}
	case "sub":
		if f := exportSubscription(sniBugs); f != "" {
			exported = append(exported, f)
		}
	case "raw":
		if f := exportRaw(proxies); f != "" {
			exported = append(exported, f)
		}
	case "csv":
		if f := exportCSV(proxies, sniBugs); f != "" {
			exported = append(exported, f)
		}
	default:
		if f := exportHTTPInjector(carrier, proxies, sniBugs); f != "" {
			exported = append(exported, f)
		}
		if f := exportV2Ray(carrier, sniBugs); f != "" {
			exported = append(exported, f)
		}
		if f := exportNapsternetV(carrier, sniBugs); f != "" {
			exported = append(exported, f)
		}
		if f := exportHTTPCustom(carrier, sniBugs); f != "" {
			exported = append(exported, f)
		}
		if f := exportSubscription(sniBugs); f != "" {
			exported = append(exported, f)
		}
		if f := exportRaw(proxies); f != "" {
			exported = append(exported, f)
		}
		if f := exportCSV(proxies, sniBugs); f != "" {
			exported = append(exported, f)
		}
	}

	fmt.Println()
	cGreen.Printf("  %s\n", strings.Repeat("═", 55))
	cPink.Printf("  EXPORTED %d FILES\n", len(exported))
	cGreen.Printf("  %s\n", strings.Repeat("─", 55))
	for _, f := range exported {
		cCyan.Printf("  → %s\n", f)
	}
	cGreen.Printf("  %s\n", strings.Repeat("═", 55))
	fmt.Println()
}

func exportHTTPInjector(carrier Carrier, proxies, sniBugs []Hit) string {
	if len(proxies) == 0 {
		return ""
	}
	path := exportPath(fmt.Sprintf("httpinjector_%s", carrier.Key)) + ".conf"
	f, err := os.Create(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	bug := ""
	if len(sniBugs) > 0 {
		bug = sniBugs[0].Host
	}
	if bug == "" && len(carrier.ZeroRated) > 0 {
		bug = carrier.ZeroRated[0]
	}

	fmt.Fprintf(f, "[DREX v0.0.1 - HTTP Injector]\n")
	fmt.Fprintf(f, "Carrier: %s\n", carrier.Name)
	fmt.Fprintf(f, "APN: %s\n", carrier.APN)
	fmt.Fprintf(f, "Generated: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
	for _, p := range proxies {
		fmt.Fprintf(f, "[ENTRY]\nProxy=%s\nPort=%d\nType=%s\nBug=%s\nLatency=%dms\nVerified=%v\n\n",
			p.IP, p.Port, p.Type, bug, p.Latency, p.Verified)
	}
	return path
}

func exportV2Ray(carrier Carrier, sniBugs []Hit) string {
	if len(sniBugs) == 0 {
		return ""
	}
	path := exportPath(fmt.Sprintf("v2ray_%s", carrier.Key)) + ".json"
	type vmessCfg struct {
		V    string `json:"v"`
		PS   string `json:"ps"`
		Add  string `json:"add"`
		Port string `json:"port"`
		ID   string `json:"id"`
		Aid  string `json:"aid"`
		Scy  string `json:"scy"`
		Net  string `json:"net"`
		Type string `json:"type"`
		Host string `json:"host"`
		Path string `json:"path"`
		TLS  string `json:"tls"`
		SNI  string `json:"sni"`
	}
	var configs []vmessCfg
	for i, s := range sniBugs {
		configs = append(configs, vmessCfg{
			V:    "2",
			PS:   fmt.Sprintf("DREX-%s-%d", carrier.Name, i+1),
			Add:  s.Host,
			Port: "443",
			ID:   generateID(s.Host),
			Aid:  "0",
			Scy:  "auto",
			Net:  "ws",
			Type: "none",
			Host: s.Host,
			Path: "/",
			TLS:  "tls",
			SNI:  s.Host,
		})
	}
	data, err := json.MarshalIndent(configs, "", "  ")
	if err != nil {
		return ""
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return ""
	}
	return path
}

func exportNapsternetV(carrier Carrier, sniBugs []Hit) string {
	if len(sniBugs) == 0 {
		return ""
	}
	path := exportPath(fmt.Sprintf("napsternetv_%s", carrier.Key)) + ".json"
	type nnCfg struct {
		ConfigType string `json:"configType"`
		Remarks    string `json:"remarks"`
		Address    string `json:"address"`
		Port       int    `json:"port"`
		Network    string `json:"network"`
		TLS        bool   `json:"tls"`
		SNI        string `json:"sni"`
		WSPath     string `json:"wsPath"`
		WSHost     string `json:"wsHost"`
	}
	var configs []nnCfg
	for i, s := range sniBugs {
		configs = append(configs, nnCfg{
			ConfigType: "V2Ray",
			Remarks:    fmt.Sprintf("DREX-%s-%d", carrier.Name, i+1),
			Address:    s.Host,
			Port:       443,
			Network:    "ws",
			TLS:        true,
			SNI:        s.Host,
			WSPath:     "/",
			WSHost:     s.Host,
		})
	}
	data, _ := json.MarshalIndent(configs, "", "  ")
	os.WriteFile(path, data, 0644)
	return path
}

func exportHTTPCustom(carrier Carrier, sniBugs []Hit) string {
	if len(sniBugs) == 0 {
		return ""
	}
	path := exportPath(fmt.Sprintf("httpcustom_%s", carrier.Key)) + ".hc"
	f, err := os.Create(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	fmt.Fprintf(f, "# DREX v0.0.1 - HTTP Custom\n# Carrier: %s\n\n", carrier.Name)
	for _, s := range sniBugs {
		fmt.Fprintf(f, "[SERVER]\nSNI=%s\nHost=%s\nPort=443\n\n", s.Host, s.Host)
	}
	return path
}

func exportSubscription(sniBugs []Hit) string {
	if len(sniBugs) == 0 {
		return ""
	}
	path := exportPath("subscription") + ".txt"
	f, err := os.Create(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	for i, s := range sniBugs {
		vmess := map[string]interface{}{
			"v": "2", "ps": fmt.Sprintf("DREX-%d", i+1),
			"add": s.Host, "port": "443",
			"id":   generateID(s.Host),
			"aid":  "0", "scy": "auto", "net": "ws",
			"type": "none", "host": s.Host,
			"path": "/", "tls": "tls",
		}
		data, _ := json.Marshal(vmess)
		encoded := base64.StdEncoding.EncodeToString(data)
		fmt.Fprintf(f, "vmess://%s\n", encoded)
	}
	return path
}

func exportRaw(proxies []Hit) string {
	if len(proxies) == 0 {
		return ""
	}
	path := exportPath("raw_proxies") + ".txt"
	f, err := os.Create(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	for _, p := range proxies {
		fmt.Fprintf(f, "%s:%d\n", p.IP, p.Port)
	}
	return path
}

func exportCSV(proxies, sniBugs []Hit) string {
	path := exportPath("results") + ".csv"
	f, err := os.Create(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write([]string{"type", "ip", "port", "host", "latency_ms", "verified", "response", "found_at"})
	for _, p := range proxies {
		w.Write([]string{
			p.Type, p.IP, fmt.Sprintf("%d", p.Port), p.Host,
			fmt.Sprintf("%d", p.Latency), fmt.Sprintf("%v", p.Verified),
			p.Response, p.Time.Format(time.RFC3339),
		})
	}
	for _, s := range sniBugs {
		w.Write([]string{
			s.Type, s.IP, fmt.Sprintf("%d", s.Port), s.Host,
			fmt.Sprintf("%d", s.Latency), fmt.Sprintf("%v", s.Verified),
			s.Response, s.Time.Format(time.RFC3339),
		})
	}
	w.Flush()
	return path
}
