package analyst

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brenu/bounty-cli/internal/db"
)

// ---------------------------------------------------------------------------
// splitIntoChunks
// ---------------------------------------------------------------------------

func TestSplitIntoChunks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		text      string
		maxChars  int
		wantCount int // expected number of chunks
	}{
		{
			name:      "text shorter than limit returns one chunk",
			text:      "hello world",
			maxChars:  100,
			wantCount: 1,
		},
		{
			name:      "text exactly at limit returns one chunk",
			text:      strings.Repeat("x", 100),
			maxChars:  100,
			wantCount: 1,
		},
		{
			// maxChars=10: "line1\n"=6 fits, adding "line2\n"=6 would make 12>10 → flush
			// "line1" → chunk 1. "line2\n"=6 fits, adding "line3"=5 → 11>10 → flush
			// "line2" → chunk 2. "line3" → chunk 3.
			name:      "newline-split produces three chunks",
			text:      "line1\nline2\nline3",
			maxChars:  10,
			wantCount: 3,
		},
		{
			name:      "single oversized line is hard-split",
			text:      strings.Repeat("a", 250),
			maxChars:  100,
			wantCount: 3,
		},
		{
			name:      "empty string returns one empty chunk",
			text:      "",
			maxChars:  100,
			wantCount: 1,
		},
		{
			name:      "multiple lines fit in one chunk",
			text:      "finding1\nfinding2\nfinding3",
			maxChars:  1000,
			wantCount: 1,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := splitIntoChunks(tc.text, tc.maxChars)
			if len(got) != tc.wantCount {
				t.Errorf("splitIntoChunks(%q, %d) returned %d chunks, want %d",
					tc.text, tc.maxChars, len(got), tc.wantCount)
			}
			for i, chunk := range got {
				if len(chunk) > tc.maxChars {
					t.Errorf("chunk %d has length %d, exceeds maxChars %d", i, len(chunk), tc.maxChars)
				}
			}
		})
	}
}

func TestSplitIntoChunks_ReconstructsContent(t *testing.T) {
	t.Parallel()
	text := "🔴 CRITICAL | rce-template | https://target.com | RCE — exec arbitrary commands\n" +
		"🔴 HIGH | ssrf-template | https://other.com | SSRF — internal network access\n"

	// With a large limit the whole text comes back intact.
	chunks := splitIntoChunks(text, 4000)
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}
	if !strings.Contains(chunks[0], "rce-template") {
		t.Error("chunk missing expected content")
	}
}

// ---------------------------------------------------------------------------
// queryLLM — uses an httptest server to avoid real network calls
// ---------------------------------------------------------------------------

func makeTestServer(t *testing.T, responseContent string, statusCode int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate basic request shape.
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)

		resp := chatResponse{
			Choices: []struct {
				Message chatResponseMessage `json:"message"`
			}{
				{Message: chatResponseMessage{Role: "assistant", Content: responseContent}},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestQueryLLM_Success(t *testing.T) {
	t.Parallel()
	want := "🔴 CRITICAL | rce-blind | https://target.com/exec | Blind RCE — remote command execution via unsanitised input"
	srv := makeTestServer(t, want, http.StatusOK)
	defer srv.Close()

	got, err := queryLLM(Config{BaseURL: srv.URL + "/v1", Model: "test-model"}, "some report content")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Content != want {
		t.Errorf("got %q, want %q", got.Content, want)
	}
}

func TestQueryLLM_NonOKStatus(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"model not found"}`)
	}))
	defer srv.Close()

	_, err := queryLLM(Config{BaseURL: srv.URL + "/v1", Model: "bad-model"}, "report")
	if err == nil {
		t.Fatal("expected error for non-200 status, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("error should mention HTTP 500, got: %v", err)
	}
}

func TestQueryLLM_EmptyChoices(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"choices":[]}`)
	}))
	defer srv.Close()

	_, err := queryLLM(Config{BaseURL: srv.URL + "/v1", Model: "model"}, "report")
	if err == nil {
		t.Fatal("expected error for empty choices, got nil")
	}
}

func TestQueryLLM_RequestContainsModelAndSystemPrompt(t *testing.T) {
	t.Parallel()
	const modelName = "hf.co/bartowski/gemma-4-e4b-it-GGUF:Q4_K_M"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req chatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}

		if req.Model != modelName {
			t.Errorf("expected model %q, got %q", modelName, req.Model)
		}
		if len(req.Messages) < 2 {
			t.Errorf("expected at least 2 messages, got %d", len(req.Messages))
		}
		if req.Messages[0].Role != "system" {
			t.Errorf("first message role should be 'system', got %q", req.Messages[0].Role)
		}
		if !strings.Contains(req.Messages[0].Content, "bug bounty") {
			t.Error("system prompt should mention 'bug bounty'")
		}
		if req.Stream {
			t.Error("stream should be false")
		}

		// Return a minimal valid response.
		w.Header().Set("Content-Type", "application/json")
		resp := chatResponse{
			Choices: []struct {
				Message chatResponseMessage `json:"message"`
			}{{Message: chatResponseMessage{Role: "assistant", Content: "NONE"}}},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	_, _ = queryLLM(Config{BaseURL: srv.URL + "/v1", Model: modelName}, "test report")
}

func TestStripEmbeddedThinking(t *testing.T) {
	t.Parallel()

	raw := "<think>Checking SQLi templates...</think>\n" +
		"🔴 HIGH | sqli-error | https://vuln.example.com | SQL Injection — database dump"

	visible, reasoning := stripEmbeddedThinking(raw)
	if len(reasoning) != 1 || !strings.Contains(reasoning[0], "Checking SQLi") {
		t.Fatalf("reasoning = %v, want one SQLi block", reasoning)
	}
	if !strings.Contains(visible, "sqli-error") {
		t.Fatalf("visible = %q, want finding line only", visible)
	}
	if strings.Contains(visible, "redacted_thinking") {
		t.Fatalf("visible still contains thinking tags: %q", visible)
	}
}

func TestStripEmbeddedThinking_ThinkTags(t *testing.T) {
	t.Parallel()

	raw := thinkOpenTag + "Evaluating XSS candidates..." + thinkCloseTag + "\n" +
		"🔴 HIGH | xss-reflected | https://vuln.example.com | Reflected XSS — session hijack"

	visible, reasoning := stripEmbeddedThinking(raw)
	if len(reasoning) != 1 || !strings.Contains(reasoning[0], "Evaluating XSS") {
		t.Fatalf("reasoning = %v, want XSS evaluation block", reasoning)
	}
	if !strings.Contains(visible, "xss-reflected") {
		t.Fatalf("visible = %q, want finding line only", visible)
	}
}

func TestQueryLLM_UsesReasoningContentField(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"message":{"role":"assistant","content":"NONE","reasoning_content":"Evaluated all templates."}}]}`)
	}))
	defer srv.Close()

	got, err := queryLLM(Config{BaseURL: srv.URL + "/v1", Model: "reasoning-model"}, "report")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Content != "NONE" {
		t.Errorf("content = %q, want NONE", got.Content)
	}
	if !strings.Contains(got.Reasoning, "Evaluated all templates") {
		t.Errorf("reasoning = %q, want evaluation trace", got.Reasoning)
	}
}

func TestQueryLLM_SendsAuthorizationWhenAPIKeySet(t *testing.T) {
	t.Parallel()
	const apiKey = "sk-test-claude-key"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+apiKey {
			t.Errorf("Authorization = %q, want %q", auth, "Bearer "+apiKey)
		}

		w.Header().Set("Content-Type", "application/json")
		resp := chatResponse{
			Choices: []struct {
				Message chatResponseMessage `json:"message"`
			}{{Message: chatResponseMessage{Role: "assistant", Content: "NONE"}}},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	_, err := queryLLM(Config{
		BaseURL: srv.URL + "/v1",
		Model:   "claude-sonnet-4",
		APIKey:  apiKey,
	}, "report")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestQueryLLM_OmitsAuthorizationWhenAPIKeyEmpty(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("Authorization should be omitted for local models, got %q", auth)
		}

		w.Header().Set("Content-Type", "application/json")
		resp := chatResponse{
			Choices: []struct {
				Message chatResponseMessage `json:"message"`
			}{{Message: chatResponseMessage{Role: "assistant", Content: "NONE"}}},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	_, err := queryLLM(Config{BaseURL: srv.URL + "/v1", Model: "local-model"}, "report")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// AnalyseReport — these tests mutate the package-level notifyRunner and must
// NOT run in parallel with each other to avoid data races on that variable.
// ---------------------------------------------------------------------------

func TestNotifyScanComplete(t *testing.T) {
	t.Parallel()

	var notifiedText string
	orig := notifyRunner
	defer func() { notifyRunner = orig }()
	notifyRunner = func(text, providerID string) error {
		notifiedText = text
		if providerID != "tel" {
			t.Errorf("expected providerID 'tel', got %q", providerID)
		}
		return nil
	}

	if err := NotifyScanComplete("Acme Corp", "tel"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "Scan complete for Acme Corp: no findings were discovered."
	if notifiedText != want {
		t.Errorf("notified text = %q, want %q", notifiedText, want)
	}
}

func TestAnalyseReport_ReturnsNone(t *testing.T) {
	srv := makeTestServer(t, "NONE", http.StatusOK)
	defer srv.Close()

	notifyCalled := false
	orig := notifyRunner
	defer func() { notifyRunner = orig }()
	notifyRunner = func(_, _ string) error {
		notifyCalled = true
		return nil
	}

	// Write a temporary report file.
	dir := t.TempDir()
	report := filepath.Join(dir, "report.md")
	if err := os.WriteFile(report, []byte("# Report\nNo findings."), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{BaseURL: srv.URL + "/v1", Model: "test-model", NotifyID: "tel"}
	if err := AnalyseReport(report, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if notifyCalled {
		t.Error("notifyRunner should not be called when LLM returns NONE")
	}
}

func TestAnalyseReport_FindingsAreDispatched(t *testing.T) {
	finding := "🔴 HIGH | sqli-error | https://vuln.example.com/search | SQL Injection — attacker can dump the database"
	raw := "<think>Reviewing SQLi candidates...</think>\n" + finding
	srv := makeTestServer(t, raw, http.StatusOK)
	defer srv.Close()

	var notifiedText string
	orig := notifyRunner
	defer func() { notifyRunner = orig }()
	notifyRunner = func(text, providerID string) error {
		notifiedText = text
		if providerID != "tel" {
			t.Errorf("expected providerID 'tel', got %q", providerID)
		}
		return nil
	}

	dir := t.TempDir()
	report := filepath.Join(dir, "report.md")
	if err := os.WriteFile(report, []byte("# Scan Report\n| HIGH | sqli-error | ... |"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{BaseURL: srv.URL + "/v1", Model: "test-model", NotifyID: "tel"}
	if err := AnalyseReport(report, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(notifiedText, "sqli-error") {
		t.Errorf("notified text should contain the finding, got: %q", notifiedText)
	}
	if strings.Contains(notifiedText, "redacted_thinking") || strings.Contains(notifiedText, "Reviewing SQLi") {
		t.Errorf("notified text should not contain reasoning, got: %q", notifiedText)
	}
}

func TestAnalyseReport_MissingReportFile(t *testing.T) {
	cfg := Config{BaseURL: "http://localhost:11434/v1", Model: "test-model", NotifyID: "tel"}
	err := AnalyseReport("/nonexistent/path/report.md", cfg)
	if err == nil {
		t.Fatal("expected error for missing report file, got nil")
	}
}

func TestAnalyseReport_ChunksLongOutput(t *testing.T) {
	// Build output that definitely exceeds MaxTelegramChars.
	longLine := strings.Repeat("🔴 CRITICAL | tpl | https://t.example.com | Finding — impact\n", 120)
	srv := makeTestServer(t, longLine, http.StatusOK)
	defer srv.Close()

	var callCount int
	orig := notifyRunner
	defer func() { notifyRunner = orig }()
	notifyRunner = func(text, _ string) error {
		callCount++
		if len(text) > MaxTelegramChars {
			t.Errorf("chunk length %d exceeds MaxTelegramChars %d", len(text), MaxTelegramChars)
		}
		return nil
	}

	dir := t.TempDir()
	report := filepath.Join(dir, "report.md")
	_ = os.WriteFile(report, []byte("# Report\nsome content"), 0644)

	cfg := Config{BaseURL: srv.URL + "/v1", Model: "test-model", NotifyID: "tel"}
	if err := AnalyseReport(report, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount < 2 {
		t.Errorf("expected multiple notify calls for long output, got %d", callCount)
	}
}

// ---------------------------------------------------------------------------
// formatFindingsForLLM
// ---------------------------------------------------------------------------

func TestFormatFindingsForLLM(t *testing.T) {
	t.Parallel()

	var f1, f2 db.NucleiFinding
	f1.TemplateID = "cve-xxx"
	f1.MatchedAt = "https://t.example.com"
	f1.Info.Name = "RCE"
	f1.Info.Severity = "critical"
	f1.Info.Description = "Remote code execution via unsanitised input"

	f2.TemplateID = "sqli-err"
	f2.MatchedAt = "https://t.example.com/search"
	f2.Info.Name = "SQL Injection"
	f2.Info.Severity = "high"

	got := formatFindingsForLLM("example.com", []db.NucleiFinding{f1, f2})

	if !strings.Contains(got, "example.com") {
		t.Errorf("output should contain root domain, got: %q", got)
	}
	if !strings.Contains(got, "[CRITICAL]") {
		t.Errorf("output should contain severity label, got: %q", got)
	}
	if !strings.Contains(got, "cve-xxx") {
		t.Errorf("output should contain template ID, got: %q", got)
	}
	if !strings.Contains(got, "Remote code execution") {
		t.Errorf("output should contain description, got: %q", got)
	}
}

func TestFormatFindingsForLLM_Empty(t *testing.T) {
	t.Parallel()
	got := formatFindingsForLLM("empty.com", nil)
	if !strings.Contains(got, "0") {
		t.Errorf("empty findings should report zero count, got: %q", got)
	}
}

// ---------------------------------------------------------------------------
// AnalyseGroupFindings — some tests mutate the package-level notifyRunner
// and must NOT run in parallel with each other.
// ---------------------------------------------------------------------------

func TestAnalyseGroupFindings_EmptyFindings(t *testing.T) {
	t.Parallel()
	result, err := AnalyseGroupFindings("example.com", nil, Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty result, got %q", result)
	}
}

func TestAnalyseGroupFindings_ReturnsNone(t *testing.T) {
	srv := makeTestServer(t, "NONE", http.StatusOK)
	defer srv.Close()

	notifyCalled := false
	orig := notifyRunner
	defer func() { notifyRunner = orig }()
	notifyRunner = func(_, _ string) error {
		notifyCalled = true
		return nil
	}

	var f db.NucleiFinding
	f.TemplateID = "cve-xxx"
	f.MatchedAt = "https://t.example.com"
	f.Info.Name = "RCE"
	f.Info.Severity = "critical"
	cfg := Config{BaseURL: srv.URL + "/v1", Model: "test-model", NotifyID: "tel"}

	result, err := AnalyseGroupFindings("example.com", []db.NucleiFinding{f}, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty result when LLM returns NONE, got %q", result)
	}
	if notifyCalled {
		t.Error("notifyRunner should not be called when LLM returns NONE")
	}
}

func TestAnalyseGroupFindings_FindingsDispatched(t *testing.T) {
	finding := "🔴 CRITICAL | cve-xxx | https://t.example.com | RCE — remote code execution"
	srv := makeTestServer(t, finding, http.StatusOK)
	defer srv.Close()

	var notifiedText string
	orig := notifyRunner
	defer func() { notifyRunner = orig }()
	notifyRunner = func(text, providerID string) error {
		notifiedText = text
		if providerID != "tel" {
			t.Errorf("expected providerID 'tel', got %q", providerID)
		}
		return nil
	}

	var f db.NucleiFinding
	f.TemplateID = "cve-xxx"
	f.MatchedAt = "https://t.example.com"
	f.Info.Name = "RCE"
	f.Info.Severity = "critical"
	cfg := Config{BaseURL: srv.URL + "/v1", Model: "test-model", NotifyID: "tel"}

	result, err := AnalyseGroupFindings("example.com", []db.NucleiFinding{f}, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != finding {
		t.Errorf("result = %q, want %q", result, finding)
	}
	if !strings.Contains(notifiedText, "[example.com]") {
		t.Errorf("notification should contain group header, got: %q", notifiedText)
	}
	if !strings.Contains(notifiedText, "cve-xxx") {
		t.Errorf("notification should contain finding, got: %q", notifiedText)
	}
}

// ---------------------------------------------------------------------------
// SendFinalReport
// ---------------------------------------------------------------------------

func TestSendFinalReport(t *testing.T) {
	var notifiedText string
	orig := notifyRunner
	defer func() { notifyRunner = orig }()
	notifyRunner = func(text, providerID string) error {
		notifiedText = text
		if providerID != "tel" {
			t.Errorf("expected providerID 'tel', got %q", providerID)
		}
		return nil
	}

	analyses := map[string]string{
		"example.com": "🔴 CRITICAL | cve-xxx | t.example.com | RCE\n🔴 HIGH | sqli | t.example.com/search | SQLi",
		"other.com":   "🔴 CRITICAL | ssrf | other.com | SSRF",
	}

	if err := SendFinalReport("Test Program", analyses, "tel"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(notifiedText, "Final Analysis Report") {
		t.Errorf("should contain final report header, got: %q", notifiedText)
	}
	if !strings.Contains(notifiedText, "📂 example.com") {
		t.Errorf("should contain group name, got: %q", notifiedText)
	}
	if !strings.Contains(notifiedText, "📂 other.com") {
		t.Errorf("should contain second group name, got: %q", notifiedText)
	}
	if !strings.Contains(notifiedText, "Summary: 2 root domain(s), 3 triaged finding(s)") {
		t.Errorf("should contain correct summary, got: %q", notifiedText)
	}
}

func TestSendFinalReport_Empty(t *testing.T) {
	var notifiedText string
	orig := notifyRunner
	defer func() { notifyRunner = orig }()
	notifyRunner = func(text, providerID string) error {
		notifiedText = text
		return nil
	}

	if err := SendFinalReport("Empty Program", nil, "tel"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(notifiedText, "no findings were discovered") {
		t.Errorf("empty report should fall back to NotifyScanComplete, got: %q", notifiedText)
	}
}
