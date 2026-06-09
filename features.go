package main

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

func runWatchMode(carrier Carrier, interval time.Duration, strategy Strategy) {
	cCyan.Printf("\n  Watch mode -- %s\n", carrier.Name)
	if interval > 0 {
		cCyan.Printf("  Interval   : %s\n", interval)
	}
	cYellow.Println("  Ctrl+C to stop\n")
	round := 0
	for {
		round++
		state := loadResults()
		proxies := state.getProxies()
		snis := state.getSNIBugs()
		if len(proxies) == 0 && len(snis) == 0 {
			cYellow.Println("  No saved results. Run a scan first.")
			return
		}
		cGreen.Printf("  [%s] Round %d -- %d proxies + %d SNI bugs\n",
			time.Now().Format("15:04:05"), round, len(proxies), len(snis))
		cGreen.Println("  " + strings.Repeat("-", 50))
		aliveProxies := make([]Hit, 0, len(proxies))
		deadP := 0
		for _, p := range proxies {
			ok := validateProxy(p.IP, p.Port, 10*time.Second)
			if ok {
				p.Verified = true
				aliveProxies = append(aliveProxies, p)
				cGreen.Printf("  ALIVE   %s:%d  [%s]  %dms\n", p.IP, p.Port, p.Type, p.Latency)
			} else {
				deadP++
				cRed.Printf("  DEAD    %s:%d\n", p.IP, p.Port)
			}
		}
		aliveSNI := make([]Hit, 0, len(snis))
		deadS := 0
		for _, s := range snis {
			ok := validateSNIBug(s.IP, s.Host, 10*time.Second)
			if ok {
				s.Verified = true
				aliveSNI = append(aliveSNI, s)
				cCyan.Printf("  ACTIVE  %s -> %s  %dms\n", s.IP, s.Host, s.Latency)
			} else {
				deadS++
				cRed.Printf("  DEAD    %s -> %s\n", s.IP, s.Host)
			}
		}
		newState := newScanState()
		newState.mu.Lock()
		newState.proxies = aliveProxies
		newState.sniBugs = aliveSNI
		newState.Carrier = state.Carrier
		newState.mu.Unlock()
		saveResults(newState)
		fmt.Println()
		cGreen.Printf("  Round %d done -- Alive: %d proxies (%d dead) | %d SNI (%d dead)\n\n",
			round, len(aliveProxies), deadP, len(aliveSNI), deadS)
		if interval == 0 {
			return
		}
		cDim.Printf("  Next check in %s...\n\n", interval)
		time.Sleep(interval)
	}
}

func runCommonSNIScan(carrier Carrier, strategy Strategy) {
	allIPs := expandAllCIDRs(carrier.IPRanges, 300)
	fmt.Println()
	cGreen.Printf("  %s\n", strings.Repeat("=", 52))
	cCyan.Printf("  Common SNI scan -- %s\n", carrier.Name)
	cGreen.Printf("  IPs       : %d\n", len(allIPs))
	cGreen.Printf("  SNI hosts : %d candidates\n", len(CommonSNI))
	cGreen.Printf("  %s\n\n", strings.Repeat("=", 52))
	state := newScanState()
	state.mu.Lock()
	state.Carrier = carrier.Name
	state.StartTime = time.Now()
	state.mu.Unlock()
	state.Scanning.Store(true)
	sem := make(chan struct{}, strategy.Concurrency)
	var wg sync.WaitGroup
	for _, ip := range allIPs {
		for _, sniHost := range CommonSNI {
			wg.Add(1)
			sem <- struct{}{}
			go func(ip, host string) {
				defer wg.Done()
				defer func() { <-sem }()
				if h := probeSNI(ip, host, strategy.Timeout); h != nil {
					h.Verified = validateSNIBug(ip, host, strategy.Timeout)
					printSNIHit(*h)
					state.addSNI(*h)
				}
				state.Scanned.Add(1)
				elapsed := time.Since(state.StartTime).Seconds()
				if elapsed > 0 {
					state.Speed.Store(int64(float64(state.Scanned.Load()) / elapsed))
				}
			}(ip, sniHost)
		}
	}
	wg.Wait()
	state.Scanning.Store(false)
	fmt.Println()
	cGreen.Println("  " + strings.Repeat("=", 52))
	cPink.Printf("  Common SNI scan complete\n")
	cGreen.Printf("  Scanned : %d probes\n", state.Scanned.Load())
	cCyan.Printf("  SNI hits: %d\n", state.sniCount())
	cGreen.Println("  " + strings.Repeat("=", 52) + "\n")
	if state.sniCount() > 0 {
		saveResults(state)
		cGreen.Println("  Results saved -> drex_results.json")
	}
}

func subnetWalk(ip string, carrier Carrier, sniHosts []string, timeout time.Duration, state *ScanState) {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return
	}
	subnet := strings.Join(parts[:3], ".") + ".0/24"
	ips := expandCIDR(subnet, 254)
	sem := make(chan struct{}, 50)
	var wg sync.WaitGroup
	for _, subIP := range ips {
		if subIP == ip {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(subIP string) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, port := range carrier.Ports {
				if h := probeHTTPProxy(subIP, port, timeout); h != nil {
					h.Verified = validateProxy(subIP, port, timeout)
					printHit(*h)
					state.addProxy(*h)
				}
			}
			for _, host := range sniHosts {
				if len(sniHosts) > 5 {
					host = sniHosts[0]
				}
				if h := probeSNI(subIP, host, timeout); h != nil {
					h.Verified = validateSNIBug(subIP, host, timeout)
					printSNIHit(*h)
					state.addSNI(*h)
					break
				}
			}
		}(subIP)
	}
	wg.Wait()
}

func printStats(state *ScanState) {
	proxies := state.getProxies()
	snis := state.getSNIBugs()
	fmt.Println()
	cGreen.Println("  " + strings.Repeat("=", 58))
	cPink.Println("  DETAILED STATISTICS")
	cGreen.Println("  " + strings.Repeat("-", 58))
	verifiedProxy := 0
	totalLatency := int64(0)
	typeCount := make(map[string]int)
	for _, p := range proxies {
		if p.Verified {
			verifiedProxy++
		}
		totalLatency += p.Latency
		typeCount[p.Type]++
	}
	workingSNI := 0
	sniHostCount := make(map[string]int)
	for _, s := range snis {
		if s.Verified {
			workingSNI++
		}
		sniHostCount[s.Host]++
	}
	cGreen.Printf("  Total proxies     : %d\n", len(proxies))
	cGreen.Printf("  Verified proxies  : %d\n", verifiedProxy)
	cGreen.Printf("  Unverified        : %d\n", len(proxies)-verifiedProxy)
	if len(proxies) > 0 {
		avg := totalLatency / int64(len(proxies))
		cGreen.Printf("  Avg latency       : %dms\n", avg)
		best := proxies[0]
		cGreen.Printf("  Best proxy        : %s:%d (%dms)\n", best.IP, best.Port, best.Latency)
	}
	fmt.Println()
	cCyan.Printf("  Total SNI bugs    : %d\n", len(snis))
	cCyan.Printf("  Working (verified): %d\n", workingSNI)
	cCyan.Printf("  Found only        : %d\n", len(snis)-workingSNI)
	if len(typeCount) > 0 {
		fmt.Println()
		cGreen.Println("  " + strings.Repeat("-", 58))
		cPink.Println("  PROXY TYPES")
		for t, c := range typeCount {
			bar := strings.Repeat("#", c)
			if len(bar) > 28 {
				bar = bar[:28]
			}
			cGreen.Printf("  %-28s [%s] %d\n", t, bar, c)
		}
	}
	if len(sniHostCount) > 0 {
		fmt.Println()
		cGreen.Println("  " + strings.Repeat("-", 58))
		cCyan.Println("  SNI HOST HITS")
		for host, c := range sniHostCount {
			cCyan.Printf("  %-38s %d hit(s)\n", host, c)
		}
	}
	cGreen.Println("  " + strings.Repeat("=", 58) + "\n")
}

func runDeepScan(carrier Carrier, strategy Strategy, state *ScanState) {
	sniHosts := make([]string, 0, len(carrier.ZeroRated)+len(CommonSNI))
	sniHosts = append(sniHosts, carrier.ZeroRated...)
	sniHosts = append(sniHosts, CommonSNI...)
	allIPs := expandAllCIDRs(carrier.IPRanges, 1000)
	fmt.Println()
	cPink.Printf("  %s\n", strings.Repeat("=", 52))
	cGreen.Printf("  DEEP SCAN -- %s\n", carrier.Name)
	cGreen.Printf("  IPs       : %d\n", len(allIPs))
	cCyan.Printf("  SNI hosts : %d (full list)\n", len(sniHosts))
	cGreen.Printf("  Payloads  : %d types\n", len(PayloadTemplates))
	cPink.Printf("  %s\n\n", strings.Repeat("=", 52))
	state.mu.Lock()
	state.StartTime = time.Now()
	state.Carrier = carrier.Name
	state.mu.Unlock()
	state.Scanning.Store(true)
	subnetDone := make(map[string]bool)
	var subnetMu sync.Mutex
	sem := make(chan struct{}, strategy.Concurrency)
	var wg sync.WaitGroup
	for _, ip := range allIPs {
		if !state.Scanning.Load() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			prevHits := state.proxyCount() + state.sniCount()
			scanIP(ip, carrier, sniHosts, strategy.Timeout, state)
			state.Scanned.Add(1)
			newHits := state.proxyCount() + state.sniCount()
			if newHits > prevHits {
				parts := strings.Split(ip, ".")
				if len(parts) == 4 {
					subnetKey := strings.Join(parts[:3], ".")
					subnetMu.Lock()
					already := subnetDone[subnetKey]
					if !already {
						subnetDone[subnetKey] = true
					}
					subnetMu.Unlock()
					if !already {
						cCyan.Printf("\n  [SUBNET] Hit at %s -- expanding %s.0/24\n", ip, subnetKey)
						go subnetWalk(ip, carrier, sniHosts[:5], strategy.Timeout, state)
					}
				}
			}
			elapsed := time.Since(state.StartTime).Seconds()
			if elapsed > 0 {
				state.Speed.Store(int64(float64(state.Scanned.Load()) / elapsed))
			}
		}(ip)
	}
	wg.Wait()
	state.Scanning.Store(false)
}
