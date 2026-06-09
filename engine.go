package main

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"
)

func expandCIDR(cidr string, maxHosts int) []string {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	var ips []string
	ip := cloneIP(network.IP)
	for network.Contains(ip) {
		last := ip[len(ip)-1]
		if last != 0 && last != 255 {
			ips = append(ips, ip.String())
			if len(ips) >= maxHosts {
				break
			}
		}
		incrementIP(ip)
	}
	return ips
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func countCIDRHosts(cidr string) int {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0
	}
	ones, bits := network.Mask.Size()
	count := 1 << uint(bits-ones)
	if count >= 2 {
		count -= 2
	}
	return count
}

func expandAllCIDRs(ranges []string, maxPerRange int) []string {
	var all []string
	for _, cidr := range ranges {
		all = append(all, expandCIDR(cidr, maxPerRange)...)
	}
	rand.Shuffle(len(all), func(i, j int) { all[i], all[j] = all[j], all[i] })
	return all
}

func resolveCarrier(key string) (Carrier, bool) {
	if c, ok := Carriers[key]; ok {
		return c, true
	}
	keys := sortedCarrierKeys()
	for i, k := range keys {
		if key == fmt.Sprintf("%d", i+1) {
			return Carriers[k], true
		}
	}
	return Carrier{}, false
}

func sortedCarrierKeys() []string {
	keys := make([]string, 0, len(Carriers))
	for k := range Carriers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func scanIP(ip string, carrier Carrier, sniHosts []string, timeout time.Duration, state *ScanState) {
	for _, port := range carrier.Ports {
		if !state.Scanning.Load() {
			return
		}
		if h := probeHTTPProxy(ip, port, timeout); h != nil {
			h.Verified = validateProxy(ip, port, timeout)
			printHit(*h)
			state.addProxy(*h)
		}
		if port != 443 {
			if h := probeHTTPSProxy(ip, port, timeout); h != nil {
				h.Verified = validateProxy(ip, port, timeout)
				printHit(*h)
				state.addProxy(*h)
			}
		}
		if port == 1080 || port == 1081 || port == 9050 {
			if h := probeSOCKS5(ip, port, timeout); h != nil {
				h.Verified = true
				printHit(*h)
				state.addProxy(*h)
			}
		}
	}

	if !state.Scanning.Load() {
		return
	}
	for _, host := range sniHosts {
		if h := probeSNI(ip, host, timeout); h != nil {
			h.Verified = validateSNIBug(ip, host, timeout)
			printSNIHit(*h)
			state.addSNI(*h)
			break
		}
	}

	if !state.Scanning.Load() {
		return
	}
	if len(sniHosts) > 0 {
		host := sniHosts[0]
		for _, payload := range PayloadTemplates {
			if h := probeHTTPInject(ip, 80, host, payload, timeout); h != nil {
				printHit(*h)
				state.addSNI(*h)
				break
			}
		}
		for _, port := range []int{80, 8080} {
			if h := probeWebSocket(ip, port, host, timeout); h != nil {
				printHit(*h)
				state.addProxy(*h)
				break
			}
		}
	}
}

func RunScan(carrier Carrier, strategy Strategy, state *ScanState) {
	state.mu.Lock()
	state.StartTime = time.Now()
	state.Carrier = carrier.Name
	state.mu.Unlock()
	state.Scanning.Store(true)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println()
		cYellow.Println("  Stopping scan...")
		state.Scanning.Store(false)
	}()

	sniHosts := make([]string, 0, len(carrier.ZeroRated)+len(CommonSNI))
	sniHosts = append(sniHosts, carrier.ZeroRated...)
	sniHosts = append(sniHosts, CommonSNI[:15]...)

	maxPerRange := 500
	if strategy.Name == "turbo" || strategy.Name == "aggressive" {
		maxPerRange = 1000
	}

	allIPs := expandAllCIDRs(carrier.IPRanges, maxPerRange)
	printScanStart(carrier, strategy, len(allIPs))

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
			scanIP(ip, carrier, sniHosts, strategy.Timeout, state)
			state.Scanned.Add(1)
			elapsed := time.Since(state.StartTime).Seconds()
			if elapsed > 0 {
				state.Speed.Store(int64(float64(state.Scanned.Load()) / elapsed))
			}
		}(ip)
	}

	wg.Wait()
	state.Scanning.Store(false)
}

func startScan(carrier Carrier, strategy Strategy, state *ScanState) {
	runBootSequence()

	stopTicker := make(chan struct{})
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if state.Scanning.Load() {
					printLiveStatus(state)
				}
			case <-stopTicker:
				return
			}
		}
	}()

	RunScan(carrier, strategy, state)

	close(stopTicker)
	fmt.Println()
	printScanSummary(state)

	if err := saveResults(state); err != nil {
		cRed.Printf("  Save failed: %v\n", err)
	} else {
		cGreen.Printf("  Results saved → drex_results.json\n\n")
	}
}
