//go:build !linux
// +build !linux

package cpu

import (
	"errors"

	"github.com/srodi/hotspot-bpf/pkg/types"
)

var errUnsupported = errors.New("cpu collector requires linux")

// Collector is a placeholder on non-Linux platforms.
type Collector struct{}

// NewCollector returns an error because eBPF is only supported on Linux.
func NewCollector() (*Collector, error) {
	return nil, errUnsupported
}

// Snapshot always fails on unsupported platforms.
func (c *Collector) Snapshot(limit int) ([]types.CPUStat, error) {
	return nil, errUnsupported
}

// Contention always fails on unsupported platforms.
func (c *Collector) Contention(limit int) ([]types.ContentionStat, error) {
	return nil, errUnsupported
}

// Reset does nothing on unsupported platforms.
func (c *Collector) Reset() error {
	return nil
}

// Close is a no-op stub.
func (c *Collector) Close() error {
	return nil
}
