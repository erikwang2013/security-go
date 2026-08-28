// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package storage

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type record struct {
	Key         string    `json:"key"`
	Count       int       `json:"count"`
	WindowStart time.Time `json:"window_start"`
	BlockUntil  time.Time `json:"block_until,omitempty"`
}

// File is a file-based persistent storage backend.
type File struct {
	mu      sync.RWMutex
	path    string
	records map[string]*record
	done    chan struct{}
	closed  bool
	dirty   bool
}

// NewFile creates or loads a file-based storage backend with periodic
// auto-save every 30 seconds to prevent data loss on crash.
func NewFile(path string) (*File, error) {
	f := &File{path: path, records: make(map[string]*record), done: make(chan struct{})}
	data, err := os.ReadFile(path)
	if err == nil {
		var loaded []record
		if json.Unmarshal(data, &loaded) == nil {
			for _, r := range loaded {
				f.records[r.Key] = &r
			}
		}
	}
	go f.autoSave(30 * time.Second)
	return f, nil
}

func (f *File) Incr(key string, window time.Duration) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	r, ok := f.records[key]
	if !ok || now.Sub(r.WindowStart) > window {
		f.records[key] = &record{Key: key, Count: 1, WindowStart: now}
		f.dirty = true
		return 1, nil
	}
	r.Count++
	f.dirty = true
	return r.Count, nil
}

func (f *File) Get(key string) (int, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if r, ok := f.records[key]; ok {
		return r.Count, nil
	}
	return 0, nil
}

func (f *File) Block(key string, duration time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.records[key]; ok {
		r.BlockUntil = time.Now().Add(duration)
	} else {
		f.records[key] = &record{Key: key, BlockUntil: time.Now().Add(duration)}
	}
	f.dirty = true
	return nil
}

func (f *File) IsBlocked(key string) (bool, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if r, ok := f.records[key]; ok {
		return time.Now().Before(r.BlockUntil), nil
	}
	return false, nil
}

func (f *File) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		close(f.done)
		f.closed = true
	}
	return f.saveLocked()
}

func (f *File) saveLocked() error {
	now := time.Now()
	var out []record
	for k, r := range f.records {
		blockAlive := !r.BlockUntil.IsZero() && now.Before(r.BlockUntil)
		windowAlive := !r.WindowStart.IsZero() && now.Sub(r.WindowStart) <= 5*time.Minute
		// ponytail: 5-min ceiling assumes windows <= 5min (matches memory.go); store window per record if longer needed
		if !blockAlive && !windowAlive {
			delete(f.records, k)
			continue
		}
		out = append(out, *r)
	}
	data, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return os.WriteFile(f.path, data, 0644)
}

func (f *File) autoSave(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-f.done:
			return
		case <-ticker.C:
			f.mu.Lock()
			if f.dirty && f.saveLocked() == nil {
				f.dirty = false
			}
			f.mu.Unlock()
		}
	}
}
