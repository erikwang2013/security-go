// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package storage

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type fileRecord struct {
	Key         string    `json:"key"`
	Count       int       `json:"count"`
	WindowStart time.Time `json:"window_start"`
	BlockUntil  time.Time `json:"block_until,omitempty"`
}

type record struct {
	count       int
	windowStart time.Time
	blockUntil  time.Time
}

// File is a file-based persistent storage backend.
type File struct {
	mu      sync.Mutex
	path    string
	records map[string]*record
	done    chan struct{}
	closed  bool
}

// NewFile creates or loads a file-based storage backend with periodic
// auto-save every 30 seconds to prevent data loss on crash.
func NewFile(path string) (*File, error) {
	f := &File{path: path, records: make(map[string]*record), done: make(chan struct{})}
	data, err := os.ReadFile(path)
	if err == nil {
		var loaded []fileRecord
		if json.Unmarshal(data, &loaded) == nil {
			for _, r := range loaded {
				f.records[r.Key] = &record{
					count:       r.Count,
					windowStart: r.WindowStart,
					blockUntil:  r.BlockUntil,
				}
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
	if !ok || now.Sub(r.windowStart) > window {
		f.records[key] = &record{count: 1, windowStart: now}
		return 1, nil
	}
	r.count++
	return r.count, nil
}

func (f *File) Get(key string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.records[key]; ok {
		return r.count, nil
	}
	return 0, nil
}

func (f *File) Block(key string, duration time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.records[key]; ok {
		r.blockUntil = time.Now().Add(duration)
	} else {
		f.records[key] = &record{blockUntil: time.Now().Add(duration)}
	}
	return nil
}

func (f *File) IsBlocked(key string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.records[key]; ok {
		return time.Now().Before(r.blockUntil), nil
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
	var out []fileRecord
	for k, r := range f.records {
		out = append(out, fileRecord{
			Key: k, Count: r.count,
			WindowStart: r.windowStart, BlockUntil: r.blockUntil,
		})
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
			_ = f.saveLocked()
			f.mu.Unlock()
		}
	}
}
