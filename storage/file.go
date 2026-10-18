// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type record struct {
	Key         string        `json:"key"`
	Count       int           `json:"count"`
	WindowStart time.Time     `json:"window_start"`
	Window      time.Duration `json:"window,omitempty"`
	BlockUntil  time.Time     `json:"block_until,omitempty"`
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
		f.records[key] = &record{Key: key, Count: 1, WindowStart: now, Window: window}
		f.dirty = true
		return 1, nil
	}
	r.Count++
	r.Window = window
	f.dirty = true
	return r.Count, nil
}

func (f *File) Get(key string) (int, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	r, ok := f.records[key]
	if !ok {
		return 0, nil
	}
	// Get has no window argument, so the window recorded by Incr decides
	// whether the counter is still live.
	if r.Window > 0 && time.Since(r.WindowStart) > r.Window {
		return 0, nil
	}
	return r.Count, nil
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
		windowAlive := !r.WindowStart.IsZero() && now.Sub(r.WindowStart) <= recordWindow(r)
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
	// Write to a sibling temp file and rename, so a crash mid-write cannot
	// truncate the live file: NewFile treats unreadable JSON as empty, which
	// would silently drop every ban and counter.
	tmp, err := os.CreateTemp(filepath.Dir(f.path), ".security-go-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		if name != "" {
			os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, f.path); err != nil {
		return err
	}
	name = ""
	return nil
}

// recordWindow returns the TTL stored with a counter. Files written before the
// field existed carry no window; keep their historic five-minute retirement.
func recordWindow(r *record) time.Duration {
	if r.Window > 0 {
		return r.Window
	}
	return 5 * time.Minute
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
