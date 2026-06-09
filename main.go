package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	flagMode     string
	flagOutput   string
	flagWorkers  int
	flagTimeout  int
	flagInterval string
	flagDeep     bool
)

func main() {
	root := &cobra.Command{
		Use:   "drex",
		Short: "Network Intelligence Scanner",
		Run: func(cmd *cobra.Command, args []string) {
			printBanner()
			cmd.Help()
		},
	}

	scanCmd := &cobra.Command{
		Use:   "scan [carrier]",
		Short: "Scan carrier for SNI bugs and open proxies",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			key := strings.ToLower(strings.TrimSpace(args[0]))
			strategy := getStrategy(flagMode)
			if flagWorkers > 0 {
				strategy.Concurrency = flagWorkers
			}
			if flagTimeout > 0 {
				strategy.Timeout = time.Duration(flagTimeout) * time.Second
			}
			if key == "all" {
				printBanner()
				for _, k := range sortedCarrierKeys() {
					carrier := Carriers[k]
					state := newScanState()
					cCyan.Printf("\n  Scanning %s...\n\n", carrier.Name)
					if flagDeep {
						runBootSequence()
						runDeepScan(carrier, strategy, state)
						printScanSummary(state)
						saveResults(state)
					} else {
						startScan(carrier, strategy, state)
					}
				}
				return
			}
			carrier, ok := resolveCarrier(key)
			if !ok {
				cRed.Printf("\n  Unknown carrier: %s\n", key)
				cYellow.Println("  Use 'drex list' to see carriers")
				os.Exit(1)
			}
			state := newScanState()
			if flagDeep {
				printBanner()
				runBootSequence()
				runDeepScan(carrier, strategy, state)
				printScanSummary(state)
				saveResults(state)
				cGreen.Println("  Results saved -> drex_results.json")
			} else {
				startScan(carrier, strategy, state)
			}
		},
	}
	scanCmd.Flags().StringVarP(&flagMode, "mode", "m", "balanced", "turbo|aggressive|balanced|stealth")
	scanCmd.Flags().IntVarP(&flagWorkers, "workers", "w", 0, "Override goroutine count")
	scanCmd.Flags().IntVarP(&flagTimeout, "timeout", "t", 0, "Override timeout seconds")
	scanCmd.Flags().BoolVarP(&flagDeep, "deep", "d", false, "Deep scan + subnet walker + full SNI list")

	watchCmd := &cobra.Command{
		Use:   "watch [carrier]",
		Short: "Re-validate saved results in a loop",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			key := strings.ToLower(strings.TrimSpace(args[0]))
			carrier, ok := resolveCarrier(key)
			if !ok {
				cRed.Printf("\n  Unknown carrier: %s\n", key)
				os.Exit(1)
			}
			strategy := getStrategy(flagMode)
			interval := time.Duration(0)
			if flagInterval != "" {
				var err error
				interval, err = time.ParseDuration(flagInterval)
				if err != nil {
					cRed.Printf("\n  Invalid interval: %s (use e.g. 5m, 1h)\n", flagInterval)
					os.Exit(1)
				}
			}
			printBanner()
			runWatchMode(carrier, interval, strategy)
		},
	}
	watchCmd.Flags().StringVarP(&flagInterval, "interval", "i", "", "Re-check interval e.g. 5m, 30m, 1h")
	watchCmd.Flags().StringVarP(&flagMode, "mode", "m", "balanced", "Scan mode")

	commonsniCmd := &cobra.Command{
		Use:   "commonsni [carrier]",
		Short: "Scan all common CDN SNI hosts against carrier IPs",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			key := strings.ToLower(strings.TrimSpace(args[0]))
			carrier, ok := resolveCarrier(key)
			if !ok {
				cRed.Printf("\n  Unknown carrier: %s\n", key)
				os.Exit(1)
			}
			strategy := getStrategy(flagMode)
			if flagWorkers > 0 {
				strategy.Concurrency = flagWorkers
			}
			printBanner()
			runCommonSNIScan(carrier, strategy)
		},
	}
	commonsniCmd.Flags().StringVarP(&flagMode, "mode", "m", "balanced", "Scan mode")
	commonsniCmd.Flags().IntVarP(&flagWorkers, "workers", "w", 0, "Override goroutine count")

	resultsCmd := &cobra.Command{
		Use:   "results",
		Short: "Show last saved results",
		Run: func(cmd *cobra.Command, args []string) {
			state := loadResults()
			printResults(state)
		},
	}

	statsCmd := &cobra.Command{
		Use:   "stats",
		Short: "Detailed statistics on saved results",
		Run: func(cmd *cobra.Command, args []string) {
			state := loadResults()
			printBanner()
			printStats(state)
		},
	}

	exportCmd := &cobra.Command{
		Use:   "export [carrier]",
		Short: "Export results to config files",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			key := strings.ToLower(strings.TrimSpace(args[0]))
			carrier, ok := resolveCarrier(key)
			if !ok {
				cRed.Printf("\n  Unknown carrier: %s\n", key)
				os.Exit(1)
			}
			state := loadResults()
			doExport(carrier, state, flagOutput)
		},
	}
	exportCmd.Flags().StringVarP(&flagOutput, "format", "f", "all", "all|hi|v2ray|napster|hc|sub|raw|csv")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all supported carriers",
		Run: func(cmd *cobra.Command, args []string) {
			printCarrierList()
		},
	}

	validateCmd := &cobra.Command{
		Use:   "validate [ip:port]",
		Short: "Test if a proxy is working",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			target := strings.TrimSpace(args[0])
			parts := strings.SplitN(target, ":", 2)
			if len(parts) != 2 {
				cRed.Println("\n  Usage: drex validate <ip:port>")
				os.Exit(1)
			}
			ip := parts[0]
			port := 8080
			fmt.Sscanf(parts[1], "%d", &port)
			cGreen.Printf("\n  Testing %s:%d...\n", ip, port)
			ok := validateProxy(ip, port, 10*time.Second)
			if ok {
				cGreen.Printf("  WORKING -- %s:%d is a live proxy\n\n", ip, port)
			} else {
				cRed.Printf("  DEAD -- %s:%d not responding\n\n", ip, port)
			}
		},
	}

	sniCheckCmd := &cobra.Command{
		Use:   "snicheck [ip] [host]",
		Short: "Test if IP works as SNI bug for host",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			ip := strings.TrimSpace(args[0])
			host := strings.TrimSpace(args[1])
			cGreen.Printf("\n  Testing SNI: %s -> %s\n", ip, host)
			ok := validateSNIBug(ip, host, 10*time.Second)
			if ok {
				cGreen.Printf("  WORKING -- %s responds as SNI bug on %s:443\n\n", host, ip)
			} else {
				cRed.Printf("  NOT WORKING -- %s:443 with SNI=%s failed\n\n", ip, host)
			}
		},
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Show version",
		Run: func(cmd *cobra.Command, args []string) {
			printBanner()
		},
	}

	root.AddCommand(
		scanCmd, watchCmd, commonsniCmd,
		resultsCmd, statsCmd, exportCmd,
		listCmd, validateCmd, sniCheckCmd, versionCmd,
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
