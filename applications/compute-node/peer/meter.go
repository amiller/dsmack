package main

import (
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"time"
)

// Charge the union of normal tool execution intervals. Control messages,
// resources, model thinking, workspace transfer and idle time never start it.
type agentMeter struct {
	mu           sync.Mutex
	elapsed      time.Duration
	running      time.Time
	active       map[string]json.RawMessage
	budget       int64
	limit        int64
	lastActivity time.Time
	changed      chan struct{}
}

func newAgentMeter(now time.Time, limit int64) *agentMeter {
	return &agentMeter{active: map[string]json.RawMessage{}, limit: limit, lastActivity: now, changed: make(chan struct{}, 1)}
}
func (m *agentMeter) wake() {
	select {
	case m.changed <- struct{}{}:
	default:
	}
}
func (m *agentMeter) duration(now time.Time) time.Duration {
	value := m.elapsed
	if !m.running.IsZero() {
		value += now.Sub(m.running)
	}
	return max(0, value)
}
func (m *agentMeter) used(now time.Time) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return min(m.budget, int64(math.Ceil(m.duration(now).Seconds())))
}
func (m *agentMeter) allow(budget int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if budget < m.budget || budget < 0 || budget > m.limit {
		return fmt.Errorf("invalid active guest budget")
	}
	m.budget = budget
	m.wake()
	return nil
}
func (m *agentMeter) begin(id json.RawMessage, now, admitUntil time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !admitUntil.IsZero() && !now.Before(admitUntil) {
		return fmt.Errorf("guest is draining; resume on the next guest")
	}
	if len(id) == 0 || string(id) == "null" {
		return fmt.Errorf("tool request requires an id")
	}
	if _, exists := m.active[string(id)]; exists {
		return fmt.Errorf("duplicate active tool request")
	}
	if m.duration(now) >= time.Duration(m.budget)*time.Second {
		return fmt.Errorf("active guest credit exhausted")
	}
	if len(m.active) == 0 {
		m.running = now
	}
	m.active[string(id)] = append(json.RawMessage(nil), id...)
	m.lastActivity = now
	m.wake()
	return nil
}
func (m *agentMeter) finish(id json.RawMessage, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.active[string(id)]; !exists {
		return
	}
	delete(m.active, string(id))
	if len(m.active) == 0 {
		m.elapsed = m.duration(now)
		m.running = time.Time{}
		m.lastActivity = now
	}
	m.wake()
}
func (m *agentMeter) freeze(now time.Time) []json.RawMessage {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]json.RawMessage, 0, len(m.active))
	for _, id := range m.active {
		ids = append(ids, id)
	}
	m.elapsed = m.duration(now)
	m.running = time.Time{}
	m.active = map[string]json.RawMessage{}
	m.lastActivity = now
	m.wake()
	return ids
}
func (m *agentMeter) deadline(now, wall, admitUntil time.Time, idle time.Duration) (time.Time, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	next, reason := wall, "drain"
	if len(m.active) > 0 {
		credit := now.Add(time.Duration(m.budget)*time.Second - m.duration(now))
		if credit.Before(next) {
			next, reason = credit, "credit"
		}
	} else {
		if !admitUntil.IsZero() && admitUntil.Before(next) {
			next, reason = admitUntil, "drain"
		}
		if last := m.lastActivity.Add(idle); last.Before(next) {
			next, reason = last, "idle"
		}
	}
	return next, reason
}
