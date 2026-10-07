//go:build !unix

package state

// oNoFollow is not available outside unix (Linux is the only supported target).
const oNoFollow = 0
