//go:build unix

package state

import "syscall"

// oNoFollow makes reads of relay.state / relay.state.prev refuse a symbolic link in final position.
const oNoFollow = syscall.O_NOFOLLOW
