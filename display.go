package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
)

var (
	cGreen  = color.New(color.FgHiGreen)
	cPink   = color.New(color.FgHiMagenta)
	cCyan   = color.New(color.FgHiCyan)
	cYellow = color.New(color.FgYellow)
	cWhite  = color.New(color.FgHiWhite)
	cRed    = color.New(color.FgHiRed)
	cDim    = color.New(color.FgWhite, color.Faint)
)

func printBanner() {
	fmt.Println()
	cPink.Println("  ██████╗ ██████╗ ███████╗██╗  ██╗")
	cPink.Println("  ██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝")
	cGreen.Println("  ██║  ██║██████╔╝█████╗   ╚███╔╝ ")
	cGreen.Println("  ██║  ██║██╔══██╗██╔══╝   ██╔██╗ ")
	cCyan.Println("  ██████╔╝██║  ██║███████╗██╔╝ ██╗")
	cCyan.Println("  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝")
	fmt.Println()
	cWhite.Print("  DREX ")
	cGreen.Print("v0.0.1  ")
	cDim.Println("Network Intelligence Scanner")
	cDim.Println("  " + strings.Repeat("─", 48))
	fmt.Println()
}

func runBootSequence() {
	steps := []struct{ label string }{
		{"Loading carrier database    "},
		{"Initializing goroutine pool "},
		{"Priming SNI probe vectors   "},
		{"Configuring proxy validators"},
		{"Setting up export pipeline  "},
		{"All systems operational     "},
	}
	total := len(steps)
	for i, step := range steps {
		pct := (i + 1) * 100 / total
		filled := (i + 1) * 32 / total
		bar := strings.Repeat("█", filled) + strings.Repeat("░", 32-filled)
		fmt.Printf("\r  %s %s %d%%  ",
			cGreen.Sprint(bar),
			cDim.Sprint(step.label),
			pct,
		)
		time.Sleep(120 * time.Millisecond)
	}
	fmt.Println()
	fmt.Println()
	cGreen.Println("  ► DREX READY")
	fmt.Println()
}

func printScanStart(carrier Carrier, strategy Strategy, totalIPs int) {
	fmt.Println()
	cPink.Printf("  %s\n", strings.Repeat("▓", 52))
	cGreen.Printf("  TARGET    : %s\n", carrier.Name)
	cCyan.Printf("  STRATEGY  : %s\n", strings.ToUpper(strategy.Name))
	cGreen.Printf("  GOROUTINES: %d\n", strategy.Concurrency)
	cGreen.Printf("  TIMEOUT   : %ds per probe\n", int(strategy.Timeout.Seconds()))
	cGreen.Printf("  TOTAL IPs : %d\n", totalIPs)
	cCyan.Printf("  SNI HOSTS : %d candidates\n", len(carrier.ZeroRated)+15)
	cGreen.Printf("  PAYLOADS  : %d inject types\n", len(PayloadTemplates))
	cPink.Printf("  %s\n", strings.Repeat("▓", 52))
	fmt.Println()
}

func printLiveStatus(state *ScanState) {
	state.mu.RLock()
	startTime := state.StartTime
	carrier := state.Carrier
	state.mu.RUnlock()
	elapsed := time.Since(startTime)
	h := int(elapsed.Hours())
	m := int(elapsed.Minutes()) % 60
	s := int(elapsed.Seconds()) % 60
	fmt.Printf("\r  [%s] %s | %s | %s | %s | %s     ",
		cDim.Sprintf("%02d:%02d:%02d", h, m, s),
		cGreen.Sprintf("%s", carrier),
		cYellow.Sprintf("IPs:%d", state.Scanned.Load()),
		cPink.Sprintf("HITS:%d", state.Hits.Load()),
		cCyan.Sprintf("SNI:%d", state.sniCount()),
		cGreen.Sprintf("%d/s", state.Speed.Load()),
	)
}

func printHit(h Hit) {
	fmt.Println()
	verified := ""
	if h.Verified {
		verified = cGreen.Sprint("  ✓ VERIFIED")
	} else {
		verified = cYellow.Sprint("  ? UNVERIFIED")
	}
	cPink.Printf("  [HIT]  ")
	cWhite.Printf("%-18s", h.IP)
	cYellow.Printf(":%-6d", h.Port)
	cCyan.Printf("  %-22s", h.Type)
	cDim.Printf("  %dms", h.Latency)
	fmt.Print(verified)
	if h.Response != "" {
		cDim.Printf("  %s", h.Response)
	}
	fmt.Println()
}

func printSNIHit(h Hit) {
	fmt.Println()
	status := ""
	if h.Verified {
		status = cGreen.Sprint("  ✓ WORKING")
	} else {
		status = cYellow.Sprint("  ? NOT CONFIRMED")
	}
	cCyan.Printf("  [SNI]  ")
	cWhite.Printf("%-18s", h.IP)
	cCyan.Printf("  %-36s", h.Host)
	cDim.Printf("  %dms", h.Latency)
	fmt.Print(status)
	if h.Response != "" {
		cDim.Printf("  %s", h.Response)
	}
	fmt.Println()
}

func printScanSummary(state *ScanState) {
	state.mu.RLock()
	startTime := state.StartTime
	carrier := state.Carrier
	state.mu.RUnlock()
	elapsed := time.Since(startTime)
	fmt.Println()
	cGreen.Println("  " + strings.Repeat("═", 55))
	cPink.Println("  SCAN COMPLETE")
	cGreen.Println("  " + strings.Repeat("─", 55))
	cGreen.Printf("  Carrier    : %s\n", carrier)
	cGreen.Printf("  Duration   : %s\n", elapsed.Round(time.Second))
	cGreen.Printf("  Scanned    : %d IPs\n", state.Scanned.Load())
	cPink.Printf("  Total Hits : %d\n", state.Hits.Load())
	cGreen.Printf("  Proxies    : %d\n", state.proxyCount())
	cCyan.Printf("  SNI Bugs   : %d\n", state.sniCount())
	if elapsed.Milliseconds() > 0 {
		avg := state.Scanned.Load() * 1000 / elapsed.Milliseconds()
		cGreen.Printf("  Avg Speed  : %d IPs/s\n", avg)
	}
	cGreen.Println("  " + strings.Repeat("═", 55))
	fmt.Println()
}

func printResults(state *ScanState) {
	printBanner()
	proxies := state.getProxies()
	sniBugs := state.getSNIBugs()

	cGreen.Println("  " + strings.Repeat("═", 65))
	cPink.Printf("  PROXY HITS  (%d found)\n", len(proxies))
	cGreen.Println("  " + strings.Repeat("─", 65))
	if len(proxies) == 0 {
		cDim.Println("  No proxies found yet. Run a scan first.")
	} else {
		cDim.Printf("  %-18s  %-6s  %-22s  %-8s  %s\n", "IP", "PORT", "TYPE", "MS", "VERIFIED")
		for _, p := range proxies {
			vLabel := cRed.Sprint("✗")
			if p.Verified {
				vLabel = cGreen.Sprint("✓")
			}
			cGreen.Printf("  %-18s  ", p.IP)
			cYellow.Printf("%-6d  ", p.Port)
			cCyan.Printf("%-22s  ", p.Type)
			cDim.Printf("%-8d  ", p.Latency)
			fmt.Printf("%s\n", vLabel)
		}
	}

	fmt.Println()
	cGreen.Println("  " + strings.Repeat("─", 65))
	cCyan.Printf("  SNI BUG HOSTS  (%d found)\n", len(sniBugs))
	cGreen.Println("  " + strings.Repeat("─", 65))
	if len(sniBugs) == 0 {
		cDim.Println("  No SNI bugs found yet.")
	} else {
		cDim.Printf("  %-18s  %-36s  %-8s  %s\n", "IP", "HOST", "MS", "STATUS")
		for _, s := range sniBugs {
			statusLabel := cYellow.Sprint("FOUND   ")
			if s.Verified {
				statusLabel = cGreen.Sprint("WORKING ")
			}
			cGreen.Printf("  %-18s  ", s.IP)
			cCyan.Printf("%-36s  ", s.Host)
			cDim.Printf("%-8d  ", s.Latency)
			fmt.Printf("%s", statusLabel)
			if s.Response != "" {
				cDim.Printf("  %s", s.Response)
			}
			fmt.Println()
		}
	}
	cGreen.Println("  " + strings.Repeat("═", 65))
	fmt.Println()
}

func printCarrierList() {
	printBanner()
	cGreen.Println("  " + strings.Repeat("═", 62))
	cPink.Printf("  SUPPORTED CARRIERS (%d)\n", len(Carriers))
	cGreen.Println("  " + strings.Repeat("─", 62))
	keys := sortedCarrierKeys()
	for i, k := range keys {
		c := Carriers[k]
		total := 0
		for _, cidr := range c.IPRanges {
			total += countCIDRHosts(cidr)
		}
		cCyan.Printf("  [%02d] ", i+1)
		cGreen.Printf("%-12s  ", k)
		cWhite.Printf("%-26s  ", c.Name)
		cYellow.Printf("(%s)  ", c.Country)
		cDim.Printf("~%dk IPs\n", total/1000)
	}
	cGreen.Println("  " + strings.Repeat("─", 62))
	cDim.Println("  drex scan econet  |  drex scan 1  |  drex scan all")
	cGreen.Println("  " + strings.Repeat("═", 62))
	fmt.Println()
}
