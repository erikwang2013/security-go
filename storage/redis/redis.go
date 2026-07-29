package redis

import (
	"context"
	"time"

	"github.com/erikwang2013/security-go/storage"
	"github.com/redis/go-redis/v9"
)

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
	ctx := context.Background()
	pipe := r.client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return int(incr.Val()), nil
}

func (r *Backend) Get(key string) (int, error) {
	val, err := r.client.Get(context.Background(), key).Int()
	if err == redis.Nil {
		return 0, nil
	}
	return val, err
}

func (r *Backend) Block(key string, duration time.Duration) error {
	return r.client.Set(context.Background(), "blocked:"+key, "1", duration).Err()
}

func (r *Backend) IsBlocked(key string) (bool, error) {
	val, err := r.client.Exists(context.Background(), "blocked:"+key).Result()
	return val > 0, err
}

func (r *Backend) Close() error {
	return r.client.Close()
}
