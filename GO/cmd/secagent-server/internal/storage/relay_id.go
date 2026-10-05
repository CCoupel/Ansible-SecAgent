package storage

import (
	"fmt"
	"log"
	"regexp"
)

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
			log.Printf("[SECURITY WARNING] relay node with a malformed relay_id ignored: relay_id=%q (delete it: it is never routed)", n.RelayID)
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
