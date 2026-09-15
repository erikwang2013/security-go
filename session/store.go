// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

// Package session detects token-session abuse: a stolen token replayed from
// another client (客户端被劫持), a login from an unseen network (异地登录) and
// tampered request parameters (篡改数据).
package session

import (
	"sync"
	"time"
)

// Store persists token-bound session state and per-user login locations.
// MemoryStore is the built-in implementation; back it with Redis or a database
// to share sessions across instances.
type Store interface {
	// Save stores value under key for ttl.
	Save(key string, value []byte, ttl time.Duration) error
	// Load returns the value for key, or (nil, nil) when absent or expired.
	Load(key string) ([]byte, error)
	// Delete removes key.
	Delete(key string) error
}

// Session is the client binding recorded when a token is issued.
type Session struct {
	IP          string    `json:"ip"`
	UserAgent   string    `json:"ua,omitempty"`
	Fingerprint string    `json:"fp,omitempty"`
	Country     string    `json:"country,omitempty"`
	IssuedAt    time.Time `json:"issued_at"`
	LastSeen    time.Time `json:"last_seen"`
}

type entry struct {
	value   []byte
	expires time.Time
}

// MemoryStore is an in-memory Store with TTL expiry, matching
// storage.Memory. Sessions are not shared between processes.
type MemoryStore struct {
	mu      sync.RWMutex
	entries map[string]*entry
	done    chan struct{}
	closed  sync.Once
}

// NewMemoryStore creates an in-memory session store.
func NewMemoryStore() *MemoryStore {
	m := &MemoryStore{entries: make(map[string]*entry), done: make(chan struct{})}
	go m.reap(30 * time.Second)
	return m
}

// Save stores a copy of value under key for ttl.
func (m *MemoryStore) Save(key string, value []byte, ttl time.Duration) error {
	cp := make([]byte, len(value))
	copy(cp, value)
	m.mu.Lock()
	m.entries[key] = &entry{value: cp, expires: time.Now().Add(ttl)}
	m.mu.Unlock()
	return nil
}

// Load returns a copy of the value for key, or nil when absent or expired.
func (m *MemoryStore) Load(key string) ([]byte, error) {
	m.mu.RLock()
	e, ok := m.entries[key]
	m.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return nil, nil
	}
	cp := make([]byte, len(e.value))
	copy(cp, e.value)
	return cp, nil
}

// Delete removes key.
func (m *MemoryStore) Delete(key string) error {
	m.mu.Lock()
	delete(m.entries, key)
	m.mu.Unlock()
	return nil
}

// Close stops the background reaper. The store must not be used afterwards.
func (m *MemoryStore) Close() error {
	m.closed.Do(func() { close(m.done) })
	return nil
}

func (m *MemoryStore) reap(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			now := time.Now()
			m.mu.Lock()
			for k, e := range m.entries {
				if now.After(e.expires) {
					delete(m.entries, k)
				}
			}
			m.mu.Unlock()
		}
	}
}
