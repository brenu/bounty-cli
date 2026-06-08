package tools

import (
	"fmt"
	"net/url"
	"os/exec"
	"strings"
)

func CheckDependencies() error {
	tools := []string{"amass", "subfinder", "naabu", "httpx", "nuclei"}
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("missing required tool: %s", tool)
		}
	}
	return nil
}

func runTool(name string, args []string, input string) (string, error) {
	cmd := exec.Command(name, args...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s failed: %w", name, err)
	}
	return string(out), nil
}

func RunSubfinder(domain string) ([]string, error) {
	domain = cleanDomain(domain)
	out, err := runTool("subfinder", []string{"-d", domain, "-silent"}, "")
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(out), "\n"), nil
}

func RunAmass(domain string) ([]string, error) {
	domain = cleanDomain(domain)
	out, err := runTool("amass", []string{"enum", "-d", domain, "-passive", "-silent"}, "")
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(out), "\n"), nil
}

func RunNaabu(targets []string, rps uint) ([]string, error) {
	if len(targets) == 0 {
		return []string{}, nil
	}
	cleaned := make([]string, len(targets))
	for i, t := range targets {
		cleaned[i] = cleanDomain(t)
	}
	out, err := runTool("naabu", []string{"-silent", "-c", "100", "-top-ports", "100", "-rate", fmt.Sprintf("%d", rps)}, strings.Join(cleaned, "\n"))
	if err != nil {
		return nil, err
	}
	return splitNonEmptyLines(out), nil
}

func splitNonEmptyLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func RunHttpx(targets []string, rps uint) ([]string, error) {
	if len(targets) == 0 {
		return []string{}, nil
	}

	out, err := runTool("httpx", []string{"-silent", "-no-color", "-rl", fmt.Sprintf("%d", rps), "-timeout", "2"}, strings.Join(targets, "\n"))
	if err != nil {
		return nil, err
	}

	return strings.Split(strings.TrimSpace(out), "\n"), nil
}

func RunNuclei(targets []string, outputFile string, rps uint) error {
	if len(targets) == 0 {
		return nil
	}
	cmd := exec.Command("nuclei",
		"-silent",
		"-no-color",
		"-jsonl",
		"-o", outputFile,
		"-c", "100",
		"-rl", fmt.Sprintf("%d", rps),
		"-severity", "medium,high,critical",
		"-timeout", "5",
	)
	cmd.Stdin = strings.NewReader(strings.Join(targets, "\n"))
	_, err := cmd.Output()
	return err
}

func cleanDomain(d string) string {
	d = strings.TrimSpace(d)
	d = strings.TrimPrefix(d, "*.")
	if strings.Contains(d, "://") {
		if u, err := url.Parse(d); err == nil {
			return u.Hostname()
		}
	}
	return d
}
