// Package worker implements a worker fleet for concurrent job execution.
package worker

import (
	"context"
	"log/slog"
	"runtime"
	"sync"

	"github.com/database64128/shadowsocks-go/tslog"
)

// Job represents a unit of work that can be executed by the fleet of workers.
type Job interface {
	// SlogAttr returns the [slog.Attr] describing the job.
	SlogAttr() slog.Attr

	// Run executes the job.
	Run(ctx context.Context, logger *tslog.Logger)
}

type workItem struct {
	job Job
	ctx context.Context
	wg  *sync.WaitGroup
}

// Fleet manages a pool of worker goroutines to execute jobs concurrently.
type Fleet struct {
	workItemCh chan workItem
	wg         sync.WaitGroup
}

// NewFleet creates a new fleet with the specified number of worker goroutines.
//
// If size is not positive, [runtime.NumCPU] is used.
func NewFleet(logger *tslog.Logger, size int) *Fleet {
	if size <= 0 {
		size = runtime.NumCPU()
	}
	f := Fleet{
		workItemCh: make(chan workItem),
	}
	f.wg.Add(size)
	for i := range size {
		workerLogger := logger.WithAttrs(slog.Int("worker", i))
		go f.runWorker(workerLogger)
	}
	return &f
}

func (f *Fleet) runWorker(logger *tslog.Logger) {
	for item := range f.workItemCh {
		if logger.Enabled(slog.LevelDebug) {
			logger.Debug("Starting job", item.job.SlogAttr())
		}
		item.job.Run(item.ctx, logger)
		if logger.Enabled(slog.LevelDebug) {
			logger.Debug("Finished job", item.job.SlogAttr())
		}
		item.wg.Done()
	}
	f.wg.Done()
}

// Run submits the given jobs to the fleet and waits for their completion.
func (f *Fleet) Run(ctx context.Context, jobs []Job) {
	var wg sync.WaitGroup
	wg.Add(len(jobs))
	for _, job := range jobs {
		f.workItemCh <- workItem{
			job: job,
			ctx: ctx,
			wg:  &wg,
		}
	}
	wg.Wait()
}

// Close shuts down the fleet and waits for all worker goroutines to finish.
func (f *Fleet) Close() {
	close(f.workItemCh)
	f.wg.Wait()
}
