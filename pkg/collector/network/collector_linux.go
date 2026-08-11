//go:build linux
// +build linux

package network

import (
	"errors"
	"fmt"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/srodi/hotspot-bpf/pkg/types"
)

// cgroupV2Path is the unified cgroup mount the skb hooks attach to.
const cgroupV2Path = "/sys/fs/cgroup"

const resetSweepRetries = 3

// Collector owns the eBPF programs tracking per-PID network bandwidth.
// It attaches socket-ownership tracking plus egress/ingress byte accounting to
// the unified cgroup, keying all traffic (TCP/UDP/ICMP/…) by owning TGID.
type Collector struct {
	objs  network_bpfObjects
	links []link.Link
}

// NewCollector loads the network programs and attaches: the socket-create owner
// tracker, the egress and ingress accounting hooks (cgroup_skb), and a
// process-exit tracepoint that prunes per-PID entries.
func NewCollector() (*Collector, error) {
	var objs network_bpfObjects
	if err := loadNetwork_bpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading network bpf objects: %w", err)
	}

	c := &Collector{objs: objs}

	attachCgroup := func(attach ebpf.AttachType, prog *ebpf.Program, name string) error {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupV2Path,
			Attach:  attach,
			Program: prog,
		})
		if err != nil {
			return fmt.Errorf("attaching %s failed: %w", name, err)
		}
		c.links = append(c.links, l)
		return nil
	}

	if err := attachCgroup(ebpf.AttachCGroupInetSockCreate, objs.TrackSockCreate, "sock_create"); err != nil {
		c.Close()
		return nil, err
	}
	// accept() hands a server a brand-new socket that sock_create never sees.
	// Attach the fexit hook so that socket gets an owner (the server's PID);
	// without it, the server's received bytes fall under PID 0.
	acceptLink, err := link.AttachTracing(link.TracingOptions{Program: objs.TrackAccept})
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("attaching inet_csk_accept fexit failed: %w", err)
	}
	c.links = append(c.links, acceptLink)
	if err := attachCgroup(ebpf.AttachCGroupInetEgress, objs.CountEgress, "egress"); err != nil {
		c.Close()
		return nil, err
	}
	if err := attachCgroup(ebpf.AttachCGroupInetIngress, objs.CountIngress, "ingress"); err != nil {
		c.Close()
		return nil, err
	}

	exitLink, err := link.Tracepoint("sched", "sched_process_exit", objs.OnExit, nil)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("attaching sched_process_exit tracepoint failed: %w", err)
	}
	c.links = append(c.links, exitLink)

	return c, nil
}

// Close releases all BPF links and objects (reverse attach order).
func (c *Collector) Close() error {
	var err error
	for i := len(c.links) - 1; i >= 0; i-- {
		if c.links[i] != nil {
			err = errors.Join(err, c.links[i].Close())
		}
	}
	return errors.Join(err, c.objs.Close())
}

// Snapshot returns the busiest PIDs by total (sent+recv) window bytes.
func (c *Collector) Snapshot(limit int) ([]types.NetworkStat, error) {
	sent, err := readByteMap(c.objs.EgressByPid)
	if err != nil {
		return nil, fmt.Errorf("reading egress map: %w", err)
	}
	recv, err := readByteMap(c.objs.IngressByPid)
	if err != nil {
		return nil, fmt.Errorf("reading ingress map: %w", err)
	}

	seen := make(map[uint32]struct{}, len(sent)+len(recv))
	for pid := range sent {
		seen[pid] = struct{}{}
	}
	for pid := range recv {
		seen[pid] = struct{}{}
	}

	stats := make([]types.NetworkStat, 0, len(seen))
	for pid := range seen {
		s := sent[pid]
		r := recv[pid]
		if s.bytes == 0 && r.bytes == 0 {
			continue
		}
		name := s.comm
		if name == "" {
			name = r.comm
		}
		if name == "" {
			if pid == 0 {
				name = "UNATTRIBUTED"
			} else {
				name = fmt.Sprintf("pid-%d", pid)
			}
		}
		stats = append(stats, types.NetworkStat{
			PID:       pid,
			Comm:      name,
			SentBytes: s.bytes,
			RecvBytes: r.bytes,
		})
	}

	sort.Slice(stats, func(i, j int) bool {
		return stats[i].SentBytes+stats[i].RecvBytes > stats[j].SentBytes+stats[j].RecvBytes
	})
	if limit > 0 && len(stats) > limit {
		stats = stats[:limit]
	}
	return stats, nil
}

// Reset clears both byte maps so the next Snapshot reflects only that window.
// The cookie_to_owner map is intentionally left intact (ownership persists).
func (c *Collector) Reset() error {
	if err := clearMap(c.objs.EgressByPid); err != nil {
		return err
	}
	return clearMap(c.objs.IngressByPid)
}

// sample is one PID's window bytes plus its in-kernel command name.
type sample struct {
	bytes uint64
	comm  string
}

func readByteMap(m *ebpf.Map) (map[uint32]sample, error) {
	out := make(map[uint32]sample)
	var pid uint32
	var st network_bpfNetstat
	iter := m.Iterate()
	for iter.Next(&pid, &st) {
		out[pid] = sample{bytes: st.Bytes, comm: commToString(st.Comm)}
	}
	return out, iter.Err()
}

func clearMap(m *ebpf.Map) error {
	for attempt := 1; attempt <= resetSweepRetries; attempt++ {
		iter := m.Iterate()
		var pid uint32
		var st network_bpfNetstat
		for iter.Next(&pid, &st) {
			if err := m.Delete(&pid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("clearing pid %d: %w", pid, err)
			}
		}
		if err := iter.Err(); err != nil {
			if errors.Is(err, ebpf.ErrIterationAborted) && attempt < resetSweepRetries {
				continue
			}
			return fmt.Errorf("iterating network map: %w", err)
		}
		return nil
	}
	return nil
}

// commToString converts the fixed-size, null-terminated C char array into a
// Go string. The generated Comm field is [16]int8; we stop at the first NUL.
func commToString(c [16]int8) string {
	b := make([]byte, 0, len(c))
	for _, ch := range c {
		if ch == 0 {
			break
		}
		b = append(b, byte(ch))
	}
	return string(b)
}
