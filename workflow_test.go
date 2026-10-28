package main

// Guards for the release workflow (.github/workflows/build.yml). Regression
// test for review N3: a git tag name may contain $( ), ; or |, so an
// expression like ${{ github.ref_name }} written straight into a run: script
// is script injection in the job that holds the release token. Expressions
// belong in env:, and no checkout leaves the token in .git/config.

import (
	"os"
	"strings"
	"testing"
)

func readWorkflow(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(".github/workflows/build.yml")
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(string(data), "\n")
}

// indentOf counts the leading spaces of a YAML line.
func indentOf(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

func TestWorkflow_NoExpressionsInRun(t *testing.T) {
	lines := readWorkflow(t)
	runs := 0
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		// "run: …" or "- run: …" starts a script.
		key := strings.TrimPrefix(trimmed, "- ")
		if !strings.HasPrefix(key, "run:") {
			continue
		}
		runs++
		if strings.Contains(key, "${{") {
			t.Errorf("line %d: expression in a one-line run: %s", i+1, trimmed)
		}
		base := indentOf(lines[i])
		for j := i + 1; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == "" {
				continue
			}
			if indentOf(lines[j]) <= base {
				break
			}
			if strings.Contains(lines[j], "${{") {
				t.Errorf("line %d: expression inside a run: script, pass it through env: %s", j+1, strings.TrimSpace(lines[j]))
			}
		}
	}
	if runs < 5 {
		t.Fatalf("found only %d run: steps; is the workflow parser still right?", runs)
	}
}

func TestWorkflow_CheckoutWithoutPersistedCredentials(t *testing.T) {
	lines := readWorkflow(t)
	checkouts := 0
	for i, line := range lines {
		if !strings.Contains(line, "uses: actions/checkout@") {
			continue
		}
		checkouts++
		// The step ends at the next "- " item on the step level or less.
		stepIndent := indentOf(line) - 2
		found := false
		for j := i + 1; j < len(lines); j++ {
			l := lines[j]
			if strings.TrimSpace(l) == "" {
				continue
			}
			if indentOf(l) <= stepIndent {
				break
			}
			if strings.TrimSpace(l) == "persist-credentials: false" {
				found = true
			}
		}
		if !found {
			t.Errorf("line %d: checkout without persist-credentials: false", i+1)
		}
	}
	if checkouts != 3 {
		t.Errorf("found %d checkouts, want 3 (verify, build, release)", checkouts)
	}
}
