// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package storage

import (
	"sync"
	"time"
)

type event struct {
	count       int
	windowStart time.Time
}

type blocked struct {
	until time.Time
}

// Memory is an in-memory storage backend with automatic TTL cleanup.
type Memory struct {
	mu      sync.RWMutex
	events  map[string]*event
	blocked map[string]*blocked
}

// NewMemory creates a new in-memory storage backend.
func NewMemory() *Memory {
	m := &Memory{
		events:  make(map[string]*event),
		blocked: make(map[string]*blocked),
	}
	go m.reap(30 * time.Second)
	return m
}

func (m *Memory) Incr(key string, window time.Duration) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	ev, ok := m.events[key]
	if !ok || now.Sub(ev.windowStart) > window {
		m.events[key] = &event{count: 1, windowStart: now}
		return 1, nil
	}
	ev.count++
	return ev.count, nil
}

func (m *Memory) Get(key string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if ev, ok := m.events[key]; ok {
		return ev.count, nil
	}
	return 0, nil
}

func (m *Memory) Block(key string, duration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blocked[key] = &blocked{until: time.Now().Add(duration)}
	return nil
}

func (m *Memory) IsBlocked(key string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if b, ok := m.blocked[key]; ok {
		return time.Now().Before(b.until), nil
	}
	return false, nil
}

func (m *Memory) Close() error { return nil }

func (m *Memory) reap(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		m.mu.Lock()
		for k, v := range m.events {
			if now.Sub(v.windowStart) > 5*time.Minute {
				delete(m.events, k)
			}
		}
		for k, v := range m.blocked {
			if now.After(v.until) {
				delete(m.blocked, k)
			}
		}
		m.mu.Unlock()
	}
}
