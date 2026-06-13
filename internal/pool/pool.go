// Package pool provides a concurrent worker pool for processing groups of
// targets with a configurable concurrency limit. It handles the common pattern
// of running a function against each group while limiting the number of
// concurrent executions.
package pool

import (
	"sync"

	"github.com/brenu/bounty-cli/internal/group"
)

// Result holds the outcome of processing one group.
type Result struct {
	Index int
	Items []string
	Err   error
}

// RunGroups processes each group through workFn, using up to concurrency
// goroutines. When concurrency <= 1, workFn is called sequentially in the
// caller's goroutine — no goroutines, channels, or mutexes are used.
//
// concurrency is automatically capped to len(groups) to avoid wasting slots.
// Results are returned in the same order as the input groups.
func RunGroups(groups []group.Group, concurrency int, workFn func(group.Group) ([]string, error)) []Result {
	n := len(groups)
	results := make([]Result, n)
	if n == 0 {
		return results
	}

	if concurrency <= 1 {
		// Sequential path: zero goroutines, zero channels, zero mutexes.
		for i, g := range groups {
			items, err := workFn(g)
			results[i] = Result{Index: i, Items: items, Err: err}
		}
		return results
	}

	// Cap concurrency to number of groups — never spawn more workers than work.
	if concurrency > n {
		concurrency = n
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for i, g := range groups {
		wg.Add(1)
		go func(idx int, grp group.Group) {
			defer wg.Done()
			sem <- struct{}{}       // acquire slot
			defer func() { <-sem }() // release slot

			items, err := workFn(grp)
			results[idx] = Result{Index: idx, Items: items, Err: err}
		}(i, g)
	}

	wg.Wait()
	return results
}
