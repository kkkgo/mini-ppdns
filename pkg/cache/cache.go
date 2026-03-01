/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package cache

import (
	"sync/atomic"
	"time"

	"github.com/kkkgo/mini-ppdns/pkg/concurrent_lru"
	"github.com/kkkgo/mini-ppdns/pkg/concurrent_map"
)

const (
	defaultCleanerInterval = time.Second * 10
)

type Key interface {
	concurrent_lru.Hashable
}

type Value interface {
	any
}

// Cache is a simple map cache that stores values in memory.
// It is safe for concurrent use.
type Cache[K Key, V Value] struct {
	opts Opts

	closed      atomic.Bool
	closeNotify chan struct{}
	m           *concurrent_map.Map[K, *elem[V]]
}

type Opts struct {
	Size            int
	CleanerInterval time.Duration
}

func (opts *Opts) init() {
	if opts.Size == 0 {
		opts.Size = 1024
	}
	if opts.CleanerInterval == 0 {
		opts.CleanerInterval = defaultCleanerInterval
	}
}

type elem[V Value] struct {
	v              V
	expirationTime time.Time
}

// New initializes a Cache.
// The minimum size is 1024.
// cleanerInterval specifies the interval that Cache scans
// and discards expired values. If cleanerInterval <= 0, a default
// interval will be used.
func New[K Key, V Value](opts Opts) *Cache[K, V] {
	opts.init()
	c := &Cache[K, V]{
		closeNotify: make(chan struct{}),
		m:           concurrent_map.NewMapCache[K, *elem[V]](opts.Size),
	}
	go c.gcLoop(opts.CleanerInterval)
	return c
}

// Close the inner cleaner of this cache.
func (c *Cache[K, V]) Close() error {
	if ok := c.closed.CompareAndSwap(false, true); ok {
		close(c.closeNotify)
	}
	return nil
}

func (c *Cache[K, V]) Get(key K) (v V, expirationTime time.Time, ok bool) {
	c.m.TestAndSet(key, func(ev *elem[V], hasEntry bool) (newV *elem[V], setV, delV bool) {
		if !hasEntry {
			return nil, false, false
		}
		if ev.expirationTime.Before(time.Now()) {
			return nil, false, true
		}
		v = ev.v
		expirationTime = ev.expirationTime
		ok = true
		return nil, false, false
	})
	return
}

// Call f through all entries. If f returns an error, the same error is returned
// by Range.
func (c *Cache[K, V]) Range(f func(key K, v V, expirationTime time.Time) error) error {
	cf := func(key K, v *elem[V]) (newV *elem[V], setV bool, delV bool, err error) {
		return nil, false, false, f(key, v.v, v.expirationTime)
	}
	return c.m.RangeDo(cf)
}

// Store this kv in cache. If expirationTime is before time.Now(),
// Store is an noop.
func (c *Cache[K, V]) Store(key K, v V, expirationTime time.Time) {
	now := time.Now()
	if now.After(expirationTime) {
		return
	}

	e := &elem[V]{
		v:              v,
		expirationTime: expirationTime,
	}
	c.m.Set(key, e)
}

func (c *Cache[K, V]) gcLoop(interval time.Duration) {
	if interval <= 0 {
		interval = defaultCleanerInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.closeNotify:
			return
		case now := <-ticker.C:
			c.gc(now)
		}
	}
}

func (c *Cache[K, V]) gc(now time.Time) {
	var expiredKeys []K
	f := func(key K, v *elem[V]) bool {
		if now.After(v.expirationTime) {
			expiredKeys = append(expiredKeys, key)
		}
		return true
	}
	c.m.Range(f)
	for _, k := range expiredKeys {
		c.m.Del(k)
	}
}

// Return the current size of this cache.
func (c *Cache[K, V]) Len() int {
	return c.m.Len()
}

// Remove all stored entries from this cache.
func (c *Cache[K, V]) Flush() {
	c.m.Flush()
}
