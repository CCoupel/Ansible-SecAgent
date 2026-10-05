package storage

import (
	"fmt"
	"log"
	"regexp"
	"sync"
)

// hostnameShape mirrors the hostnames accepted from relays (events, snapshots).
var hostnameShape = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$`)

// maxIgnoredWarned bounds the memory of the "already reported" identifiers: a heavily damaged
// database must not make it grow without limit.
const maxIgnoredWarned = 10000

var (
	ignoredMu       sync.Mutex
	ignoredWarned   = make(map[string]struct{}) // kind\x00id already reported (<= maxIgnoredWarned)
	ignoredOverflow int64                       // malformed identifiers seen beyond the bound
)

// IgnoredOverflow returns how many malformed identifiers were ignored beyond the reported bound.
func IgnoredOverflow() int64 {
	ignoredMu.Lock()
	defer ignoredMu.Unlock()
	return ignoredOverflow
}

// warnIgnoredOnce reports a malformed identifier once per id and process. After maxIgnoredWarned
// distinct ids, ONE aggregated warning is logged and further ids are only counted (the rows are
// still ignored: the filtering never depends on this bookkeeping).
func warnIgnoredOnce(kind, id string) {
	key := kind + "\x00" + id
	ignoredMu.Lock()
	if _, seen := ignoredWarned[key]; seen {
		ignoredMu.Unlock()
		return
	}
	if len(ignoredWarned) >= maxIgnoredWarned {
		ignoredOverflow++
		first := ignoredOverflow == 1
		ignoredMu.Unlock()
		if first {
			log.Printf("[SECURITY WARNING] more than %d malformed identifiers ignored: further ones are counted, not listed (the database is badly damaged)", maxIgnoredWarned)
		}
		return
	}
	ignoredWarned[key] = struct{}{}
	ignoredMu.Unlock()
	log.Printf("[SECURITY WARNING] %s with a malformed identifier ignored (never routed, delete it): %q", kind, id)
}

// validRoute reports whether a relay_routing row is made of well-formed identifiers only: the
// hostname, the declaring relay and every element of its chain end up in Ansible group names,
// hostvars, logs and task routing.
func validRoute(hostname, relayID string, chain []string) bool {
	if !hostnameShape.MatchString(hostname) || !ValidRelayID(relayID) {
		return false
	}
	for _, c := range chain {
		if !ValidRelayID(c) {
			return false
		}
	}
	return true
}

// relayIDShape is the only accepted form of a relay_id (the same as REPEATER_ID, token subjects,
// snapshots and events): it ends up in logs, environment variables, hook files and Ansible group
// names, so it must be inert.
var relayIDShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)

// ValidRelayID reports whether s is a well-formed relay_id.
func ValidRelayID(s string) bool { return relayIDShape.MatchString(s) }

// ListValidRelayNodes is ListRelayNodes without the rows whose relay_id is malformed (rows that
// predate the validation): they are ignored with a warning instead of reaching the inventory, the
// snapshots or the routing. They stay visible to ListRelayNodes so that an admin can delete them.
func (s *Store) ListValidRelayNodes() ([]RelayNode, error) {
	nodes, err := s.ListRelayNodes()
	if err != nil {
		return nil, err
	}
	out := nodes[:0:0]
	for _, n := range nodes {
		if !ValidRelayID(n.RelayID) {
			warnIgnoredOnce("relay node", n.RelayID)
			continue
		}
		out = append(out, n)
	}
	return out, nil
}

func checkRelayID(relayID string) error {
	if !ValidRelayID(relayID) {
		return fmt.Errorf("invalid relay_id (length %d)", len(relayID))
	}
	return nil
}
