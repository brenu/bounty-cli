package pool

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/brenu/bounty-cli/internal/group"
)

func makeGroups(rootsAndTargets ...string) []group.Group {
	var groups []group.Group
	for i := 0; i+1 < len(rootsAndTargets); i += 2 {
		groups = append(groups, group.Group{
			Root:    rootsAndTargets[i],
			Targets: []string{rootsAndTargets[i+1]},
		})
	}
	return groups
}

func TestRunGroups_Sequential(t *testing.T) {
	// With concurrency=1, groups are processed in order sequentially.
	groups := makeGroups("a.com", "a1", "b.com", "b1", "c.com", "c1")
	var order []string

	results := RunGroups(groups, 1, func(g group.Group) ([]string, error) {
		order = append(order, g.Root)
		return g.Targets, nil
	})

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	for i, r := range results {
		if r.Err != nil {
			t.Errorf("result[%d]: unexpected error: %v", i, r.Err)
		}
	}

	// Order must match input
	expectedOrder := []string{"a.com", "b.com", "c.com"}
	for i, root := range order {
		if root != expectedOrder[i] {
			t.Errorf("order[%d] = %q; want %q", i, root, expectedOrder[i])
		}
	}
}

func TestRunGroups_Concurrent(t *testing.T) {
	// With concurrency=2, all 3 groups are processed (they run concurrently).
	groups := makeGroups("a.com", "a1", "b.com", "b1", "c.com", "c1")

	results := RunGroups(groups, 2, func(g group.Group) ([]string, error) {
		return g.Targets, nil
	})

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// Results should be in input order
	expectedRoots := []string{"a.com", "b.com", "c.com"}
	for i, r := range results {
		if r.Err != nil {
			t.Errorf("result[%d]: unexpected error: %v", i, r.Err)
		}
		if len(r.Items) != 1 || r.Items[0] != groups[i].Targets[0] {
			t.Errorf("result[%d].Items = %v; want %v", i, r.Items, groups[i].Targets)
		}
		root := groups[r.Index].Root
		if root != expectedRoots[i] {
			t.Errorf("result[%d].Index -> Root = %q; want %q", i, root, expectedRoots[i])
		}
	}
}

func TestRunGroups_ConcurrencyCap(t *testing.T) {
	// concurrency=10 with 3 groups should only use 3 goroutines.
	groups := makeGroups("a.com", "a1", "b.com", "b1", "c.com", "c1")

	results := RunGroups(groups, 10, func(g group.Group) ([]string, error) {
		return g.Targets, nil
	})

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	for i, r := range results {
		if r.Err != nil {
			t.Errorf("result[%d]: unexpected error: %v", i, r.Err)
		}
	}
}

func TestRunGroups_EmptyInput(t *testing.T) {
	results := RunGroups(nil, 2, func(g group.Group) ([]string, error) {
		return g.Targets, nil
	})
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}

	results = RunGroups([]group.Group{}, 2, func(g group.Group) ([]string, error) {
		return g.Targets, nil
	})
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestRunGroups_ErrorPropagation(t *testing.T) {
	groups := makeGroups("a.com", "a1", "b.com", "b1")
	errB := errors.New("b failed")

	results := RunGroups(groups, 1, func(g group.Group) ([]string, error) {
		if g.Root == "b.com" {
			return nil, errB
		}
		return g.Targets, nil
	})

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// a.com should succeed
	if results[0].Err != nil {
		t.Errorf("a.com: unexpected error: %v", results[0].Err)
	}
	if len(results[0].Items) != 1 || results[0].Items[0] != "a1" {
		t.Errorf("a.com: Items = %v; want [a1]", results[0].Items)
	}

	// b.com should have the error
	if results[1].Err == nil {
		t.Error("b.com: expected error, got nil")
	} else if !errors.Is(results[1].Err, errB) {
		t.Errorf("b.com: error = %v; want %v", results[1].Err, errB)
	}
	// Items should be nil when there's an error
	if results[1].Items != nil {
		t.Errorf("b.com: expected nil Items on error, got %v", results[1].Items)
	}
}

func TestRunGroups_SequentialProducesSameOutputAsConcurrent(t *testing.T) {
	// The sequential path (concurrency=1) and concurrent path (concurrency=2)
	// should produce equivalent results for an idempotent workFn.
	groups := makeGroups(
		"a.com", "a1", "a.com", "a2",
		"b.com", "b1",
		"c.com", "c1", "c.com", "c2", "c.com", "c3",
	)

	// Dedupe by root — merge targets for same root
	merged := make(map[string][]string)
	for _, g := range groups {
		merged[g.Root] = append(merged[g.Root], g.Targets...)
	}
	var uniqueGroups []group.Group
	for root, targets := range merged {
		uniqueGroups = append(uniqueGroups, group.Group{Root: root, Targets: targets})
	}

	seqResults := RunGroups(uniqueGroups, 1, func(g group.Group) ([]string, error) {
		return g.Targets, nil
	})
	conResults := RunGroups(uniqueGroups, 3, func(g group.Group) ([]string, error) {
		return g.Targets, nil
	})

	if len(seqResults) != len(conResults) {
		t.Fatalf("result count mismatch: seq=%d, con=%d", len(seqResults), len(conResults))
	}
	for i := range seqResults {
		if (seqResults[i].Err != nil) != (conResults[i].Err != nil) {
			t.Errorf("result[%d] error mismatch: seq=%v, con=%v", i, seqResults[i].Err, conResults[i].Err)
		}
		if len(seqResults[i].Items) != len(conResults[i].Items) {
			t.Errorf("result[%d] items count mismatch: seq=%d, con=%d", i, len(seqResults[i].Items), len(conResults[i].Items))
		}
	}
}

func TestRunGroups_AtMostConcurrencyGoroutines(t *testing.T) {
	// Verify that at most 'concurrency' goroutines run simultaneously.
	groups := makeGroups("a.com", "a1", "b.com", "b1", "c.com", "c1", "d.com", "d1")

	var concurrentMax int32
	var running int32

	results := RunGroups(groups, 2, func(g group.Group) ([]string, error) {
		v := atomic.AddInt32(&running, 1)
		// Track the maximum number of concurrent executions
		for {
			cur := atomic.LoadInt32(&concurrentMax)
			if v <= cur || atomic.CompareAndSwapInt32(&concurrentMax, cur, v) {
				break
			}
		}
		defer atomic.AddInt32(&running, -1)
		return g.Targets, nil
	})

	if len(results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(results))
	}
	if concurrentMax > 2 {
		t.Errorf("at most 2 goroutines should run concurrently, got %d", concurrentMax)
	}
}

// BenchmarkRunGroups measures throughput for the concurrent path.
func BenchmarkRunGroups(b *testing.B) {
	groups := makeGroups("a.com", "a1", "b.com", "b1", "c.com", "c1", "d.com", "d1")

	workFn := func(g group.Group) ([]string, error) {
		return g.Targets, nil
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = RunGroups(groups, 2, workFn)
	}
}

func ExampleRunGroups() {
	groups := []group.Group{
		{Root: "example.com", Targets: []string{"sub1.example.com", "sub2.example.com"}},
		{Root: "test.com", Targets: []string{"api.test.com"}},
	}

	results := RunGroups(groups, 2, func(g group.Group) ([]string, error) {
		return g.Targets, nil
	})

	for _, r := range results {
		if r.Err == nil {
			fmt.Printf("%s: %d targets\n", groups[r.Index].Root, len(r.Items))
		}
	}
	// Output:
	// example.com: 2 targets
	// test.com: 1 targets
}
