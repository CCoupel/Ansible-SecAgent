//go:build race

package state

// raceFactor relaxes the performance thresholds under the race detector (5-10x slower).
const raceFactor = 8
