// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package storage

import (
	"sync"
	"time"
)

type event struct {
	count       int
	windowStart time.Time
	window      time.Duration
}

type blocked struct {
	until time.Time
}

// Memory is an in-memory storage backend with automatic TTL cleanup.
type Memory struct {
	mu      sync.RWMutex
	events  map[string]*event
	blocked map[string]*blocked
	done    chan struct{}
	closed  sync.Once
}

// NewMemory creates a new in-memory storage backend.
func NewMemory() *Memory {
	m := &Memory{
		events:  make(map[string]*event),
		blocked: make(map[string]*blocked),
		done:    make(chan struct{}),
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
		m.events[key] = &event{count: 1, windowStart: now, window: window}
		return 1, nil
	}
	ev.count++
	ev.window = window
	return ev.count, nil
}

func (m *Memory) Get(key string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ev, ok := m.events[key]
	if !ok {
		return 0, nil
	}
	// Get has no window argument, so the window recorded by Incr decides
	// whether the counter is still live.
	if ev.window > 0 && time.Since(ev.windowStart) > ev.window {
		return 0, nil
	}
	return ev.count, nil
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

// Close stops the background reaper. The backend must not be used afterwards.
func (m *Memory) Close() error {
	m.closed.Do(func() { close(m.done) })
	return nil
}

func (m *Memory) reap(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			m.reapOnce(time.Now())
		}
	}
}

// reapOnce drops entries whose own window has elapsed. Each counter carries
// the window it was created with: a fixed five-minute deadline dropped
// longer-lived entries (Signer's replay nonces live for 2*MaxSkew = 10m).
func (m *Memory) reapOnce(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.events {
		if now.Sub(v.windowStart) > v.window {
			delete(m.events, k)
		}
	}
	for k, v := range m.blocked {
		if now.After(v.until) {
			delete(m.blocked, k)
		}
	}
}
