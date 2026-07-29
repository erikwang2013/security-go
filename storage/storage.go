package storage

import "time"

// Backend is the pluggable storage interface for IP blacklisting.
type Backend interface {
	Incr(key string, window time.Duration) (int, error)
	Get(key string) (int, error)
	Block(key string, duration time.Duration) error
	IsBlocked(key string) (bool, error)
	Close() error
}
