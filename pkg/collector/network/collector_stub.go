//go:build !linux
// +build !linux

package network

import (
	"errors"

	"github.com/srodi/hotspot-bpf/pkg/types"
)

var errUnsupported = errors.New("network collector requires linux")

// Collector is a placeholder on non-Linux platforms.
type Collector struct{}

// NewCollector returns an error because eBPF is only supported on Linux.
func NewCollector() (*Collector, error) { return nil, errUnsupported }

// Snapshot always fails on unsupported platforms.
func (c *Collector) Snapshot(limit int) ([]types.NetworkStat, error) { return nil, errUnsupported }

// Reset does nothing on unsupported platforms.
func (c *Collector) Reset() error { return nil }

// Close is a no-op stub.
func (c *Collector) Close() error { return nil }
