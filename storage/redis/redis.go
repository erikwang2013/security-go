// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package redis

import (
	"context"
	"time"

	"github.com/erikwang2013/security-go/storage"
	"github.com/redis/go-redis/v9"
)

const blockedPrefix = "blocked:"

// incrWindowScript increments the counter and sets the window on the first
// increment only. Expiring on every call made the window slide: a client that
// kept failing never saw its count reset, unlike Memory and File.
var incrWindowScript = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
if n == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return n
`)

// Backend is a Redis-backed storage backend.
type Backend struct {
	client *redis.Client
}

// New creates a new Redis storage backend.
func New(addr, password string, db int) *Backend {
	return &Backend{
		client: redis.NewClient(&redis.Options{
			Addr: addr, Password: password, DB: db,
		}),
	}
}

// Ensure Backend implements storage.Backend.
var _ storage.Backend = (*Backend)(nil)

func (r *Backend) Incr(key string, window time.Duration) (int, error) {
	ms := window.Milliseconds()
	if ms < 0 {
		ms = 0
	}
	n, err := incrWindowScript.Run(context.Background(), r.client, []string{key}, ms).Int()
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (r *Backend) Get(key string) (int, error) {
	val, err := r.client.Get(context.Background(), key).Int()
	if err == redis.Nil {
		return 0, nil
	}
	return val, err
}

func (r *Backend) Block(key string, duration time.Duration) error {
	return r.client.Set(context.Background(), blockedPrefix+key, "1", duration).Err()
}

func (r *Backend) IsBlocked(key string) (bool, error) {
	val, err := r.client.Exists(context.Background(), blockedPrefix+key).Result()
	return val > 0, err
}

func (r *Backend) Close() error {
	return r.client.Close()
}
