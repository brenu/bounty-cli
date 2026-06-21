package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/brenu/bounty-cli/internal/analyst"
	"github.com/brenu/bounty-cli/internal/api"
	"github.com/brenu/bounty-cli/internal/db"
	"github.com/brenu/bounty-cli/internal/group"
	"github.com/brenu/bounty-cli/internal/pool"
	"github.com/brenu/bounty-cli/internal/reporter"
	"github.com/brenu/bounty-cli/internal/scope"
	"github.com/brenu/bounty-cli/internal/tools"
)

const nucleiResultsFile = "nuclei_results.jsonl"

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(value string) error {
	for _, v := range strings.Split(value, ",") {
		v = strings.TrimSpace(v)
		if v != "" {
			*s = append(*s, v)
		}
	}
	return nil
}

func containsStdinFlag(flags stringList) bool {
	for _, f := range flags {
		if f == "-" {
			return true
		}
	}
	return false
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func stdinIsPiped() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return stat.Mode()&os.ModeCharDevice == 0
}

func readFQDNs(r io.Reader) ([]string, error) {
	var fqdns []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, v := range strings.Split(line, ",") {
			v = strings.TrimSpace(v)
			if v != "" {
				fqdns = append(fqdns, v)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return fqdns, nil
}

func collectFQDNs(flags stringList) ([]string, error) {
	var fromFlags []string
	readStdin := stdinIsPiped()
	for _, f := range flags {
		if f == "-" {
			readStdin = true
			continue
		}
		fromFlags = append(fromFlags, f)
	}
	var fromStdin []string
	if readStdin {
		var err error
		fromStdin, err = readFQDNs(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("reading FQDNs from stdin: %w", err)
		}
	}
	return dedupeStrings(append(fromFlags, fromStdin...)), nil
}

func scopesFromFQDNs(fqdns []string) []api.Scope {
	scopes := make([]api.Scope, len(fqdns))
	for i, f := range fqdns {
		scopes[i] = api.Scope{
			Endpoint: f,
			Type:     api.AssetType{Value: "Domain"},
			Tier:     api.Tier{Value: "In Scope"},
		}
	}
	return scopes
}

// wildcardScope converts a scope to use wildcard matching so discovered
// subdomains pass the scope filter. If the endpoint lacks a "*." prefix,
// it is added. The type is set to Wildcard.
func wildcardScope(s api.Scope) api.Scope {
	if !strings.HasPrefix(s.Endpoint, "*.") {
		s.Endpoint = "*." + s.Endpoint
	}
	s.Type = api.AssetType{Value: "Wildcard"}
	return s
}

func main() {
	programID := flag.String("program-id", "", "Program ID")
	target := flag.String("target", "", "Direct target domain or wildcard (skips Intigriti)")
	programName := flag.String("program-name", "", "Program name for reports (required with --fqdn)")
	var fqdnFlags stringList
	flag.Var(&fqdnFlags, "fqdn", "FQDN to scan (repeatable; use - for stdin; skips Intigriti)")
	dbFile := flag.String("db", "bounty.db", "Database filename")
	skipRecon := flag.Bool("skip-recon", true, "Skip subdomain recon phase")
	llmURL := flag.String("llm-url", "http://localhost:11434/v1", "Base URL for the OpenAI-compatible LLM endpoint")
	llmModel := flag.String("llm-model", "hf.co/bartowski/gemma-4-e4b-it-GGUF:Q4_K_M", "LLM model name")
	llmAPIKey := flag.String("llm-api-key", "", "Bearer token for the LLM API (overrides LLM_API_KEY env var)")
	notifyID := flag.String("notify-id", "tel", "notify provider ID for Telegram (matches id: in provider-config.yaml)")
	skipAnalysis := flag.Bool("skip-analysis", false, "Skip LLM triage analysis and Telegram notification")
	skipNaabu := flag.Bool("skip-naabu", false, "Skip naabu port scan (httpx will probe 80/443 directly)")
	concurrency := flag.Uint("concurrency", 1, "Number of concurrent root-domain groups to process (1 = sequential)")
	realtimeNotify := flag.Bool("realtime-notify", false, "Notify per root-domain group in realtime as nuclei scans complete (requires --concurrency > 1)")
	flag.Parse()

	if (*programID != "" || *target != "") && (stdinIsPiped() || containsStdinFlag(fqdnFlags)) {
		fmt.Println("Error: piped/stdin FQDNs cannot be combined with --program-id or --target")
		os.Exit(1)
	}

	fqdns, err := collectFQDNs(fqdnFlags)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	inputModes := 0
	if *programID != "" {
		inputModes++
	}
	if *target != "" {
		inputModes++
	}
	if len(fqdns) > 0 {
		inputModes++
	}
	if inputModes == 0 {
		fmt.Println("Error: One of --program-id, --target, or --fqdn must be specified")
		os.Exit(1)
	}
	if inputModes > 1 {
		fmt.Println("Error: --program-id, --target, and --fqdn are mutually exclusive")
		os.Exit(1)
	}
	if len(fqdns) > 0 && *programName == "" {
		fmt.Println("Error: --program-name is required when using --fqdn")
		os.Exit(1)
	}

	if err := tools.CheckDependencies(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	database, err := db.NewDatabase(*dbFile)
	if err != nil {
		fmt.Printf("Database error: %v\n", err)
		os.Exit(1)
	}

	var reportName string
	var scopes []api.Scope
	var rps uint = 100

	if len(fqdns) > 0 {
		fmt.Printf("[*] Using %d explicit FQDN(s) for program: %s\n", len(fqdns), *programName)
		reportName = *programName
		scopes = scopesFromFQDNs(fqdns)
		if !*skipRecon {
			for i := range scopes {
				scopes[i] = wildcardScope(scopes[i])
			}
		}
	} else if *target != "" {
		fmt.Printf("[*] Using direct target: %s\n", *target)
		reportName = *target
		scopes = []api.Scope{
			{
				Endpoint: *target,
				Type:     api.AssetType{Value: "Wildcard"},
				Tier:     api.Tier{Value: "In Scope"},
			},
		}
	} else {
		token := os.Getenv("INTIGRITI_TOKEN")
		if token == "" {
			fmt.Println("INTIGRITI_TOKEN environment variable not set")
			os.Exit(1)
		}

		client := api.NewIntigritiClient(token, "")
		fmt.Printf("[*] Fetching program details for: %s\n", *programID)
		program, err := client.GetProgram(*programID)
		if err != nil {
			fmt.Printf("API error: %v\n", err)
			os.Exit(1)
		}
		reportName = program.Name
		scopes = program.Domains.GetScopes()
		if program.RulesOfEngagement.Content.TestingRequirements.MaxRPS > 0 {
			rps = program.RulesOfEngagement.Content.TestingRequirements.MaxRPS
		}
	}

	fmt.Printf("[*] Discovered %d total assets\n", len(scopes))
	scopeManager := scope.NewScopeManager(scopes)

	fmt.Printf("[*] Program/Target: %s\n", reportName)
	fmt.Printf("[*] Applying Rate Limit: %d RPS\n", rps)

	initialTargets := scopeManager.GetInitialTargets()
	fmt.Printf("[*] Found %d initial targets\n", len(initialTargets))

	var allSubdomains []string
	if *skipRecon {
		fmt.Println("[*] Skipping Recon Phase as requested...")
		if len(fqdns) > 0 {
			allSubdomains = fqdns
		} else {
			allSubdomains = initialTargets
		}
	} else {
		fmt.Println("[*] Starting Recon Phase...")
		for _, target := range initialTargets {
			fmt.Printf("[+] Running recon on: %s\n", target)
			if subs, err := tools.RunSubfinder(target); err == nil {
				allSubdomains = append(allSubdomains, subs...)
			}
			if subs, err := tools.RunAmass(target); err == nil {
				allSubdomains = append(allSubdomains, subs...)
			}
		}
	}

	var filtered []string
	for _, s := range allSubdomains {
		if scopeManager.IsAllowed(s) {
			filtered = append(filtered, s)
		}
	}
	database.SaveDomains(filtered)

	// --- Group by root domain ---
	targetGroups := group.ByRootDomain(filtered)
	effectiveConcurrency := int(*concurrency)
	if effectiveConcurrency < 1 {
		effectiveConcurrency = 1
	}
	useConcurrency := effectiveConcurrency > 1 && len(targetGroups) > 1

	if *realtimeNotify && !useConcurrency {
		fmt.Println("Error: --realtime-notify requires --concurrency > 1 and multiple root-domain groups")
		os.Exit(1)
	}

	fmt.Println("[*] Starting Live Host Discovery...")
	var openPorts []string
	var naabuResults []pool.Result

	if *skipNaabu {
		fmt.Println("[*] Skipping naabu port scan as requested (httpx will probe 80/443)...")
	} else if useConcurrency {
		fmt.Printf("[+] Running port scan (naabu, top 100) across %d groups (concurrency=%d)...\n", len(targetGroups), effectiveConcurrency)
		naabuResults = pool.RunGroups(targetGroups, effectiveConcurrency, func(g group.Group) ([]string, error) {
			return tools.RunNaabu(g.Targets, rps)
		})
		for _, r := range naabuResults {
			if r.Err != nil {
				fmt.Printf("[!] Naabu error for %s: %v\n", targetGroups[r.Index].Root, r.Err)
			} else {
				openPorts = append(openPorts, r.Items...)
			}
		}
		fmt.Printf("[*] Found %d open ports across all groups\n", len(openPorts))
	} else {
		fmt.Println("[+] Running port scan (naabu, top 100)...")
		var err error
		openPorts, err = tools.RunNaabu(filtered, rps)
		if err != nil {
			fmt.Printf("[!] Naabu scan error: %v\n", err)
		}
		fmt.Printf("[*] Found %d open ports\n", len(openPorts))
	}

	var liveHosts []string

	if useConcurrency {
		// Build httpx input per group: if naabu produced ports for a group, use those;
		// otherwise fall back to the original subdomains for that group.
		httpxInputGroups := make([]group.Group, len(targetGroups))
		for i, g := range targetGroups {
			var targets []string
			if !*skipNaabu && i < len(naabuResults) && len(naabuResults[i].Items) > 0 {
				targets = naabuResults[i].Items
			} else {
				targets = g.Targets
			}
			httpxInputGroups[i] = group.Group{Root: g.Root, Targets: targets}
		}

		fmt.Printf("[+] Probing live hosts (httpx) across %d groups (concurrency=%d)...\n", len(httpxInputGroups), effectiveConcurrency)
		httpxResults := pool.RunGroups(httpxInputGroups, effectiveConcurrency, func(g group.Group) ([]string, error) {
			return tools.RunHttpx(g.Targets, rps)
		})
		for _, r := range httpxResults {
			if r.Err != nil {
				fmt.Printf("[!] Httpx error for %s: %v\n", httpxInputGroups[r.Index].Root, r.Err)
			} else {
				liveHosts = append(liveHosts, r.Items...)
			}
		}
		liveHosts = dedupeStrings(liveHosts)
		fmt.Printf("[*] Found %d live hosts\n", len(liveHosts))
	} else {
		httpxTargets := openPorts
		if len(openPorts) == 0 {
			httpxTargets = filtered
		}
		var err error
		liveHosts, err = tools.RunHttpx(httpxTargets, rps)
		if err != nil {
			fmt.Printf("[!] Httpx probe error: %v\n", err)
		}
		fmt.Printf("[*] Found %d live hosts\n", len(liveHosts))
	}

	var newFindings []db.NucleiFinding
	allFindings := []db.NucleiFinding{}
	var groupAnalyses map[string]string // populated only when --realtime-notify is active

	if len(liveHosts) > 0 {
		fmt.Println("[*] Starting Nuclei Scan...")

		var onGroupComplete func(idx int, root string, path string)
		if *realtimeNotify && useConcurrency {
			apiKey := *llmAPIKey
			if apiKey == "" {
				apiKey = os.Getenv("LLM_API_KEY")
			}
			cfg := analyst.Config{
				BaseURL:  *llmURL,
				Model:    *llmModel,
				APIKey:   apiKey,
				NotifyID: *notifyID,
			}

			groupAnalyses = make(map[string]string)

			var mu sync.Mutex
			onGroupComplete = func(idx int, root string, path string) {
				findings, err := reporter.ParseNucleiOutput(path)
				if err != nil {
					fmt.Printf("[!] Error parsing nuclei output for %s: %v\n", root, err)
					return
				}
				if len(findings) == 0 {
					return
				}

				// Filter & save new findings (mutex-protected to prevent SQLite locking)
				var newOnes []db.NucleiFinding
				mu.Lock()
				for _, f := range findings {
					if isNew, _ := database.IsNewFinding(&f); isNew {
						newOnes = append(newOnes, f)
					}
				}
				if len(newOnes) > 0 {
					database.SaveFindings(newOnes)
				}
				mu.Unlock()

				if len(newOnes) == 0 {
					fmt.Printf("[*] %s: no new findings to triage.\n", root)
					return
				}

				fmt.Printf("[*] %s: triaging %d new finding(s)...\n", root, len(newOnes))
				analysis, err := analyst.AnalyseGroupFindings(root, newOnes, cfg)
				if err != nil {
					fmt.Printf("[!] %s: LLM triage error: %v\n", root, err)
					return
				}
				if analysis == "" {
					fmt.Printf("[*] %s: no qualifying findings after triage.\n", root)
					return
				}

				mu.Lock()
				groupAnalyses[root] = analysis
				mu.Unlock()
			}
		}

		if useConcurrency {
			liveGroups := group.ByRootDomain(liveHosts)
			allFindings = runNucleiConcurrent(liveGroups, effectiveConcurrency, rps, onGroupComplete)
		} else {
			tools.RunNuclei(liveHosts, nucleiResultsFile, rps)
			var err error
			allFindings, err = reporter.ParseNucleiOutput(nucleiResultsFile)
			if err != nil {
				fmt.Printf("Error parsing nuclei output: %v\n", err)
			}
		}

		seenInSession := make(map[string]bool)
		for _, f := range allFindings {
			key := fmt.Sprintf("%s-%s", f.TemplateID, f.MatchedAt)
			if seenInSession[key] {
				continue
			}
			seenInSession[key] = true

			if isNew, _ := database.IsNewFinding(&f); isNew {
				newFindings = append(newFindings, f)
			}
		}
	} else {
		fmt.Println("[!] No live hosts found, skipping Nuclei scan.")
	}

	fmt.Printf("[*] Found %d new vulnerabilities\n", len(newFindings))

	reportPath := reporter.GetUniqueReportPath("reports", reportName)
	if *realtimeNotify && useConcurrency {
		rep := reporter.NewReportGenerator(reportName, filtered, liveHosts, allFindings, false)
		rep.Generate(reportPath)
	} else {
		rep := reporter.NewReportGenerator(reportName, filtered, liveHosts, newFindings, true)
		rep.Generate(reportPath)
	}
	database.SaveFindings(allFindings)

	fmt.Printf("[!] Pipeline completed. Report: %s\n", reportPath)

	if !*skipAnalysis {
		if *realtimeNotify && useConcurrency {
			if err := analyst.SendFinalReport(reportName, groupAnalyses, *notifyID); err != nil {
				fmt.Printf("[!] Final report notification error: %v\n", err)
			}
		} else if len(newFindings) == 0 {
			if err := analyst.NotifyScanComplete(reportName, *notifyID); err != nil {
				fmt.Printf("[!] Telegram notification error: %v\n", err)
			}
		} else {
			apiKey := *llmAPIKey
			if apiKey == "" {
				apiKey = os.Getenv("LLM_API_KEY")
			}
			cfg := analyst.Config{
				BaseURL:  *llmURL,
				Model:    *llmModel,
				APIKey:   apiKey,
				NotifyID: *notifyID,
			}
			if err := analyst.AnalyseReport(reportPath, cfg); err != nil {
				fmt.Printf("[!] LLM analysis error: %v\n", err)
			}
		}
	}

	if len(liveHosts) > 0 {
		if err := os.Remove(nucleiResultsFile); err != nil && !os.IsNotExist(err) {
			fmt.Printf("[!] Failed to remove %s: %v\n", nucleiResultsFile, err)
		}
	}

}

// runNucleiConcurrent runs nuclei per group, each writing to a separate temp
// JSONL file. When onGroupComplete is non-nil, it is called after each group's
// nuclei scan finishes (with the semaphore slot already released) so the
// caller can process per-group results while other groups are still scanning.
func runNucleiConcurrent(liveGroups []group.Group, concurrency int, rps uint,
	onGroupComplete func(idx int, root string, path string)) []db.NucleiFinding {
	if len(liveGroups) == 0 {
		return nil
	}

	tmpDir, err := os.MkdirTemp("", "nuclei_results_*")
	if err != nil {
		fmt.Printf("[!] Failed to create temp dir: %v\n", err)
		return nil
	}
	defer os.RemoveAll(tmpDir)

	type groupOutput struct {
		index int
		path  string
		err   error
	}

	outputs := make([]groupOutput, len(liveGroups))
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for i, g := range liveGroups {
		wg.Add(1)
		go func(idx int, grp group.Group) {
			defer wg.Done()
			sem <- struct{}{} // acquire slot

			outPath := filepath.Join(tmpDir, fmt.Sprintf("nuclei_%d.jsonl", idx))
			fmt.Printf("  [nuclei] Scanning %s (%d targets)\n", grp.Root, len(grp.Targets))

			err := tools.RunNuclei(grp.Targets, outPath, rps)
			<-sem // release slot before callback so other groups can start

			if err != nil {
				outputs[idx] = groupOutput{index: idx, err: err}
				return
			}
			outputs[idx] = groupOutput{index: idx, path: outPath}

			if onGroupComplete != nil {
				onGroupComplete(idx, grp.Root, outPath)
			}
		}(i, g)
	}
	wg.Wait()

	var allFindings []db.NucleiFinding
	allMap := make(map[string]bool) // dedup across groups
	for _, out := range outputs {
		if out.err != nil {
			fmt.Printf("[!] Nuclei error for group %d: %v\n", out.index, out.err)
			continue
		}
		findings, err := reporter.ParseNucleiOutput(out.path)
		if err != nil {
			fmt.Printf("[!] Error parsing nuclei output for group %d: %v\n", out.index, err)
			continue
		}
		for _, f := range findings {
			key := fmt.Sprintf("%s-%s", f.TemplateID, f.MatchedAt)
			if !allMap[key] {
				allMap[key] = true
				allFindings = append(allFindings, f)
			}
		}
	}
	return allFindings
}
