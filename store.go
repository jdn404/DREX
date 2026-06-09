package main

import (
	"encoding/json"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type ScanState struct {
	mu        sync.RWMutex
	proxies   []Hit
	sniBugs   []Hit
	Scanned   atomic.Int64
	Hits      atomic.Int64
	Speed     atomic.Int64
	Scanning  atomic.Bool
	Carrier   string
	StartTime time.Time
}

func newScanState() *ScanState {
	return &ScanState{}
}

func (s *ScanState) addProxy(h Hit) {
	s.mu.Lock()
	s.proxies = append(s.proxies, h)
	s.mu.Unlock()
	s.Hits.Add(1)
}

func (s *ScanState) addSNI(h Hit) {
	s.mu.Lock()
	for _, existing := range s.sniBugs {
		if existing.IP == h.IP && existing.Host == h.Host {
			s.mu.Unlock()
			return
		}
	}
	s.sniBugs = append(s.sniBugs, h)
	s.mu.Unlock()
	s.Hits.Add(1)
}

func (s *ScanState) getProxies() []Hit {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Hit, len(s.proxies))
	copy(result, s.proxies)
	sort.Slice(result, func(i, j int) bool {
		return result[i].Latency < result[j].Latency
	})
	return result
}

func (s *ScanState) getSNIBugs() []Hit {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Hit, len(s.sniBugs))
	copy(result, s.sniBugs)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Verified != result[j].Verified {
			return result[i].Verified
		}
		return result[i].Latency < result[j].Latency
	})
	return result
}

func (s *ScanState) proxyCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.proxies)
}

func (s *ScanState) sniCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sniBugs)
}

type ResultFile struct {
	Proxies  []Hit     `json:"proxies"`
	SNIBugs  []Hit     `json:"sni_bugs"`
	ScanTime time.Time `json:"scan_time"`
	Carrier  string    `json:"carrier"`
}

func saveResults(state *ScanState) error {
	rf := ResultFile{
		Proxies:  state.getProxies(),
		SNIBugs:  state.getSNIBugs(),
		ScanTime: time.Now(),
		Carrier:  state.Carrier,
	}
	data, err := json.MarshalIndent(rf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("drex_results.json", data, 0644)
}

func loadResults() *ScanState {
	state := newScanState()
	data, err := os.ReadFile("drex_results.json")
	if err != nil {
		return state
	}
	var rf ResultFile
	if err := json.Unmarshal(data, &rf); err != nil {
		return state
	}
	state.mu.Lock()
	state.proxies = rf.Proxies
	state.sniBugs = rf.SNIBugs
	state.Carrier = rf.Carrier
	state.mu.Unlock()
	return state
}
