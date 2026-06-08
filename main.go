package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/brenu/bounty-cli/internal/analyst"
	"github.com/brenu/bounty-cli/internal/api"
	"github.com/brenu/bounty-cli/internal/db"
	"github.com/brenu/bounty-cli/internal/reporter"
	"github.com/brenu/bounty-cli/internal/scope"
	"github.com/brenu/bounty-cli/internal/tools"
)

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

func main() {
	programID := flag.String("program-id", "", "Program ID")
	target := flag.String("target", "", "Direct target domain or wildcard (skips Intigriti)")
	programName := flag.String("program-name", "", "Program name for reports (required with --fqdn)")
	var fqdnFlags stringList
	flag.Var(&fqdnFlags, "fqdn", "FQDN to scan (repeatable; use - for stdin; skips Intigriti and recon)")
	dbFile := flag.String("db", "bounty.db", "Database filename")
	skipRecon := flag.Bool("skip-recon", true, "Skip subdomain recon phase")
	llmURL := flag.String("llm-url", "http://localhost:11434/v1", "Base URL for the OpenAI-compatible LLM endpoint")
	llmModel := flag.String("llm-model", "hf.co/bartowski/gemma-4-e4b-it-GGUF:Q4_K_M", "LLM model name")
	llmAPIKey := flag.String("llm-api-key", "", "Bearer token for the LLM API (overrides LLM_API_KEY env var)")
	notifyID := flag.String("notify-id", "tel", "notify provider ID for Telegram (matches id: in provider-config.yaml)")
	skipAnalysis := flag.Bool("skip-analysis", false, "Skip LLM triage analysis and Telegram notification")
	skipNaabu := flag.Bool("skip-naabu", false, "Skip naabu port scan (httpx will probe 80/443 directly)")
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
	if len(fqdns) > 0 {
		fmt.Println("[*] Skipping Recon Phase (explicit FQDN list)...")
		allSubdomains = fqdns
	} else if *skipRecon {
		fmt.Println("[*] Skipping Recon Phase as requested...")
		allSubdomains = initialTargets
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

	fmt.Println("[*] Starting Live Host Discovery...")
	var openPorts []string
	if *skipNaabu {
		fmt.Println("[*] Skipping naabu port scan as requested (httpx will probe 80/443)...")
	} else {
		fmt.Println("[+] Running port scan (naabu, top 100)...")
		var err error
		openPorts, err = tools.RunNaabu(filtered, rps)
		if err != nil {
			fmt.Printf("[!] Naabu scan error: %v\n", err)
		}
		fmt.Printf("[*] Found %d open ports\n", len(openPorts))
	}

	httpxTargets := openPorts
	if len(openPorts) == 0 {
		httpxTargets = filtered
	}
	liveHosts, err := tools.RunHttpx(httpxTargets, rps)
	if err != nil {
		fmt.Printf("[!] Httpx probe error: %v\n", err)
	}
	fmt.Printf("[*] Found %d live hosts\n", len(liveHosts))

	var newFindings []db.NucleiFinding
	allFindings := []db.NucleiFinding{}

	if len(liveHosts) > 0 {
		fmt.Println("[*] Starting Nuclei Scan...")
		nucleiOut := "nuclei_results.jsonl"
		tools.RunNuclei(liveHosts, nucleiOut, rps)

		var err error
		allFindings, err = reporter.ParseNucleiOutput(nucleiOut)
		if err != nil {
			fmt.Printf("Error parsing nuclei output: %v\n", err)
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
	rep := reporter.NewReportGenerator(reportName, filtered, liveHosts, newFindings, true)
	rep.Generate(reportPath)
	database.SaveFindings(allFindings)

	fmt.Printf("[!] Pipeline completed. Report: %s\n", reportPath)

	if !*skipAnalysis {
		if len(newFindings) == 0 {
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

}
