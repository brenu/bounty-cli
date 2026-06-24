package analyst

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/brenu/bounty-cli/internal/db"
)

const (
	// MaxTelegramChars is the safe per-message character limit for Telegram.
	MaxTelegramChars = 4000
	// DefaultLLMTimeout is the HTTP timeout used when querying the local model.
	DefaultLLMTimeout = 120 * time.Second
)

const systemPrompt = `You are a senior bug bounty triage analyst. Your job is to review automated vulnerability scan reports and surface ONLY findings that represent genuine, real-world exploitable vulnerabilities worth submitting to a bug bounty program.

INCLUDE findings such as:
- Remote Code Execution (RCE), Server-Side Request Forgery (SSRF), SQL Injection, Command Injection
- Stored or Reflected XSS that bypass CSP or affect authenticated sessions
- Authentication bypass, privilege escalation, Insecure Direct Object Reference (IDOR)
- Path or directory traversal leading to sensitive file disclosure
- Exposed credentials, API keys, tokens, or secrets in HTTP responses
- Open redirects that enable phishing attacks
- Critical CVEs in actively running software versions with a public exploit

EXCLUDE findings such as:
- Missing security headers (X-Frame-Options, HSTS, CSP, X-Content-Type-Options, Referrer-Policy, etc.) unless they are part of a demonstrable exploit chain
- Cookie attribute flags (Secure, HttpOnly, SameSite) without a demonstrated exploit
- TLS/SSL configuration best-practice recommendations
- Software version disclosure without a matching publicly exploitable CVE
- Generic informational or low-severity Nuclei templates with no direct impact

For each qualifying finding output EXACTLY ONE line in this format:
🔴 [SEVERITY] | [Template ID] | [Target] | [Finding Name] — [one-sentence real-world impact]

If there are NO qualifying findings, output exactly the word: NONE

Do not include reasoning, chain-of-thought, or thinking blocks in your response. Output only the formatted findings (or NONE).`

const (
	thinkOpenTag  = "<" + "think>"
	thinkCloseTag = "</" + "think>"
)

type thinkingTag struct {
	open  string
	close string
}

var thinkingTags = []thinkingTag{
	{"<think>", "</think>"},
	{thinkOpenTag, thinkCloseTag},
	{"<thinking>", "</thinking>"},
}

// Config holds the settings for the LLM and notification pipeline.
type Config struct {
	// BaseURL is the base URL for the OpenAI-compatible LLM endpoint
	// (e.g. "http://localhost:11434/v1" or "https://openrouter.ai/api/v1").
	BaseURL string
	// Model is the model identifier to use for the chat completion request.
	Model string
	// APIKey is an optional Bearer token for authenticated LLM providers.
	// When empty, no Authorization header is sent (suitable for local models).
	APIKey string
	// NotifyID is the provider ID passed to the `notify` CLI (matches the
	// `id:` field in provider-config.yaml, e.g. "tel" for Telegram).
	NotifyID string
}

// chatRequest is the OpenAI-compatible request payload.
type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatResponse is the OpenAI-compatible response payload.
type chatResponseMessage struct {
	Role             string `json:"role"`
	Content          string `json:"content"`
	ReasoningContent string `json:"reasoning_content,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message chatResponseMessage `json:"message"`
	} `json:"choices"`
}

// llmResult holds the user-visible answer and any model reasoning kept off Telegram.
type llmResult struct {
	Content   string
	Reasoning string
}

// notifyRunner is the function used to dispatch a chunk via notify.
// It is a package-level variable so tests can replace it without exec calls.
var notifyRunner = defaultNotifyRunner

// defaultNotifyRunner pipes text into `notify -bulk -id <providerID>` via stdin.
func defaultNotifyRunner(text, providerID string) error {
	cmd := exec.Command("notify", "-bulk", "-id", providerID)
	cmd.Stdin = strings.NewReader(text)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

// NotifyScanComplete sends a generic Telegram message when a scan finishes
// without any findings, skipping LLM triage entirely.
func NotifyScanComplete(programName, providerID string) error {
	msg := fmt.Sprintf("Scan complete for %s: no findings were discovered.", programName)
	fmt.Printf("[*] Notifying scan completion (provider: %q)...\n", providerID)
	return sendViaNotify(msg, providerID)
}

// AnalyseReport reads the report at reportPath, asks the configured LLM to triage it
// for real-world bug-bounty findings, and sends qualifying findings to Telegram
// via the `notify` CLI. It is a no-op when the LLM returns "NONE".
func AnalyseReport(reportPath string, cfg Config) error {
	fmt.Println("[*] Reading report for LLM triage analysis...")
	content, err := os.ReadFile(reportPath)
	if err != nil {
		return fmt.Errorf("analyst: reading report %q: %w", reportPath, err)
	}

	fmt.Printf("[*] Querying LLM (%s) for bug-bounty triage...\n", cfg.Model)
	result, err := queryLLM(cfg, string(content))
	if err != nil {
		return fmt.Errorf("analyst: LLM query failed: %w", err)
	}

	logReasoning(result.Reasoning)

	analysis := strings.TrimSpace(result.Content)
	if strings.EqualFold(analysis, "NONE") || analysis == "" {
		fmt.Println("[*] LLM triage complete — no actionable findings to notify.")
		return nil
	}

	fmt.Printf("[*] LLM triage complete. Dispatching findings to Telegram (provider: %q)...\n", cfg.NotifyID)
	return sendViaNotify(analysis, cfg.NotifyID)
}

// AnalyseGroupFindings formats a single root-domain group's findings for the LLM,
// dispatches qualifying ones to Telegram, and returns the LLM's analysis text
// (or "" if the LLM returned NONE / findings were empty).
func AnalyseGroupFindings(rootDomain string, findings []db.NucleiFinding, cfg Config) (string, error) {
	if len(findings) == 0 {
		return "", nil
	}

	reportContent := formatFindingsForLLM(rootDomain, findings)

	fmt.Printf("[*] Querying LLM (%s) for group %s...\n", cfg.Model, rootDomain)
	result, err := queryLLM(cfg, reportContent)
	if err != nil {
		return "", fmt.Errorf("analyst: LLM query for group %s failed: %w", rootDomain, err)
	}

	logReasoning(result.Reasoning)

	analysis := strings.TrimSpace(result.Content)
	if strings.EqualFold(analysis, "NONE") || analysis == "" {
		fmt.Printf("[*] LLM triage for group %s — no actionable findings.\n", rootDomain)
		return "", nil
	}

	header := fmt.Sprintf("🔍 Partial findings for [%s]:\n\n", rootDomain)
	if err := sendViaNotify(header+analysis, cfg.NotifyID); err != nil {
		return "", fmt.Errorf("analyst: Telegram notify for group %s: %w", rootDomain, err)
	}
	return analysis, nil
}

// formatFindingsForLLM converts a slice of findings into a simple text block
// suitable for the LLM triage prompt.
func formatFindingsForLLM(rootDomain string, findings []db.NucleiFinding) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Root Domain: %s\n", rootDomain))
	sb.WriteString(fmt.Sprintf("Findings: %d\n\n", len(findings)))
	for _, f := range findings {
		sb.WriteString(fmt.Sprintf("- [%s] %s | %s | %s\n",
			strings.ToUpper(f.Info.Severity), f.TemplateID, f.MatchedAt, f.Info.Name))
		if f.Info.Description != "" {
			desc := strings.ReplaceAll(f.Info.Description, "\n", " ")
			sb.WriteString(fmt.Sprintf("  Description: %s\n", desc))
		}
	}
	return sb.String()
}

// SendFinalReport sends a consolidated final report to Telegram aggregating
// all per-group LLM triage results. If no groups produced findings, it falls
// back to NotifyScanComplete.
func SendFinalReport(programName string, groupAnalyses map[string]string, providerID string) error {
	if len(groupAnalyses) == 0 {
		return NotifyScanComplete(programName, providerID)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🏁 Final Analysis Report — %s\n\n", programName))

	totalLines := 0
	// Sort root domains for stable output
	roots := make([]string, 0, len(groupAnalyses))
	for r := range groupAnalyses {
		roots = append(roots, r)
	}
	sort.Strings(roots)

	for _, root := range roots {
		analysis := groupAnalyses[root]
		nonEmptyLines := 0
		for _, line := range strings.Split(strings.TrimSpace(analysis), "\n") {
			if strings.TrimSpace(line) != "" {
				nonEmptyLines++
			}
		}
		totalLines += nonEmptyLines
		sb.WriteString(fmt.Sprintf("📂 %s\n", root))
		sb.WriteString(analysis)
		sb.WriteString("\n\n")
	}

	sb.WriteString(fmt.Sprintf("---\nSummary: %d root domain(s), %d triaged finding(s).\n",
		len(groupAnalyses), totalLines))

	return sendViaNotify(sb.String(), providerID)
}

// queryLLM sends the report content to the OpenAI-compatible /v1/chat/completions
// endpoint and returns the model's response text.
func queryLLM(cfg Config, reportContent string) (llmResult, error) {
	payload := chatRequest{
		Model: cfg.Model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{
				Role: "user",
				Content: "Analyse the following bug bounty scan report. " +
					"Return only real-world impactful findings (CVEs,IDOR,XSS,SQLi,SSRF,XXE,RCE,BAC,Subdomain Takeover,Exposed Credentials,Prompt Injeciton,etc.) using the format specified.\n\n" +
					reportContent,
			},
		},
		Stream: false,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return llmResult{}, fmt.Errorf("marshalling request: %w", err)
	}

	url := strings.TrimRight(cfg.BaseURL, "/") + "/chat/completions"
	ctx, cancel := context.WithTimeout(context.Background(), DefaultLLMTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return llmResult{}, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return llmResult{}, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return llmResult{}, fmt.Errorf("LLM returned HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var chatResp chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return llmResult{}, fmt.Errorf("decoding LLM response: %w", err)
	}
	if len(chatResp.Choices) == 0 {
		return llmResult{}, fmt.Errorf("LLM returned empty choices array")
	}

	msg := chatResp.Choices[0].Message
	visible, embedded := stripEmbeddedThinking(msg.Content)
	reasoning := strings.TrimSpace(msg.ReasoningContent)
	if len(embedded) > 0 {
		embeddedText := strings.Join(embedded, "\n\n")
		if reasoning != "" {
			reasoning += "\n\n" + embeddedText
		} else {
			reasoning = embeddedText
		}
	}

	return llmResult{Content: visible, Reasoning: reasoning}, nil
}

func stripEmbeddedThinking(content string) (visible string, reasoning []string) {
	visible = content
	for _, tag := range thinkingTags {
		for {
			start := strings.Index(visible, tag.open)
			if start == -1 {
				break
			}
			rest := visible[start+len(tag.open):]
			endRel := strings.Index(rest, tag.close)
			if endRel == -1 {
				visible = strings.TrimSpace(visible[:start])
				break
			}
			end := start + len(tag.open) + endRel + len(tag.close)
			inner := strings.TrimSpace(visible[start+len(tag.open) : end-len(tag.close)])
			if inner != "" {
				reasoning = append(reasoning, inner)
			}
			visible = visible[:start] + visible[end:]
		}
	}
	return strings.TrimSpace(visible), reasoning
}

func logReasoning(reasoning string) {
	reasoning = strings.TrimSpace(reasoning)
	if reasoning == "" {
		return
	}
	fmt.Println("[*] LLM reasoning (local only, not sent to Telegram):")
	fmt.Println(reasoning)
}

// sendViaNotify splits the analysis into Telegram-safe chunks and dispatches
// each chunk through the notifyRunner.
func sendViaNotify(text, providerID string) error {
	chunks := splitIntoChunks(text, MaxTelegramChars)
	for i, chunk := range chunks {
		if err := notifyRunner(chunk, providerID); err != nil {
			return fmt.Errorf("analyst: notify chunk %d/%d: %w", i+1, len(chunks), err)
		}
	}
	fmt.Printf("[!] Sent %d Telegram message(s) via notify (provider: %q).\n", len(chunks), providerID)
	return nil
}

// splitIntoChunks splits text into segments of at most maxChars characters.
// It splits on newline boundaries where possible to avoid truncating lines.
// Lines longer than maxChars are hard-split at the byte boundary.
func splitIntoChunks(text string, maxChars int) []string {
	if len(text) <= maxChars {
		return []string{text}
	}

	var chunks []string
	lines := strings.Split(text, "\n")
	var buf strings.Builder

	for _, line := range lines {
		// +1 accounts for the newline we append after each line.
		if buf.Len()+len(line)+1 > maxChars {
			if buf.Len() > 0 {
				chunks = append(chunks, strings.TrimRight(buf.String(), "\n"))
				buf.Reset()
			}
			// Hard-split lines that exceed maxChars on their own.
			for len(line) > maxChars {
				chunks = append(chunks, line[:maxChars])
				line = line[maxChars:]
			}
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
	}

	if buf.Len() > 0 {
		chunks = append(chunks, strings.TrimRight(buf.String(), "\n"))
	}

	return chunks
}
