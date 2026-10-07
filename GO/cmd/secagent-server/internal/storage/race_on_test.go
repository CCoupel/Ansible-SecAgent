//go:build race

package storage

// raceFactor relaxes the dimensioning thresholds under the race detector.
const raceFactor = 8
