package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestActiveGuestMeterExcludesIdleAndPreservation(t *testing.T) {
	start := time.Unix(1000, 0)
	meter := newAgentMeter(start, 3600)
	if err := meter.allow(30); err != nil {
		t.Fatal(err)
	}
	if meter.used(start.Add(5*time.Minute)) != 0 {
		t.Fatal("idle accrued guest seconds")
	}
	id := json.RawMessage(`1`)
	if err := meter.begin(id, start.Add(300*time.Second), start.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	meter.finish(id, start.Add(302*time.Second+100*time.Millisecond))
	if got := meter.used(start.Add(time.Hour)); got != 3 {
		t.Fatal("only actual execution should be rounded", got)
	}
	if err := meter.begin(json.RawMessage(`2`), start.Add(600*time.Second), start.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	meter.finish(json.RawMessage(`2`), start.Add(600*time.Second+900*time.Millisecond))
	if got := meter.used(start.Add(1000 * time.Second)); got != 3 {
		t.Fatal("round cumulative active duration, not each tool", got)
	}
}
func TestActiveBudgetCannotShrinkOrRunPastAuthenticatedWindow(t *testing.T) {
	start := time.Unix(1000, 0)
	meter := newAgentMeter(start, 3600)
	if err := meter.allow(1); err != nil {
		t.Fatal(err)
	}
	meter.begin(json.RawMessage(`1`), start, start.Add(time.Hour))
	deadline, reason := meter.deadline(start.Add(500*time.Millisecond), start.Add(time.Hour), start.Add(time.Hour), 5*time.Minute)
	if reason != "credit" || !deadline.Equal(start.Add(time.Second)) {
		t.Fatal(deadline, reason)
	}
	meter.freeze(deadline)
	if meter.used(start.Add(time.Hour)) != 1 {
		t.Fatal("cancelled execution kept billing")
	}
	if meter.begin(json.RawMessage(`2`), deadline, start.Add(time.Hour)) == nil {
		t.Fatal("exhausted budget admitted another tool")
	}
	if meter.allow(0) == nil || meter.allow(3601) == nil {
		t.Fatal("invalid trusted budget accepted")
	}
	if err := meter.allow(31); err != nil {
		t.Fatal(err)
	}
	if err := meter.begin(json.RawMessage(`2`), deadline, start.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}
func TestDrainCompletesInflightToolButRejectsNextTool(t *testing.T) {
	start := time.Unix(1000, 0)
	cut := start.Add(10 * time.Second)
	hard := start.Add(480 * time.Second)
	meter := newAgentMeter(start, 3600)
	meter.allow(300)
	meter.begin(json.RawMessage(`1`), start, cut)
	deadline, reason := meter.deadline(cut, hard, cut, 5*time.Minute)
	if deadline.Before(hard) || reason != "drain" {
		t.Fatal("drain interrupted in-flight mutation", deadline, reason)
	}
	if meter.begin(json.RawMessage(`2`), cut, cut) == nil {
		t.Fatal("new normal tool admitted after cutoff")
	}
	meter.finish(json.RawMessage(`1`), cut.Add(time.Second))
	deadline, reason = meter.deadline(cut.Add(time.Second), hard, cut, 5*time.Minute)
	if !deadline.Equal(cut) || reason != "drain" {
		t.Fatal("finished drain did not request seal/retirement", deadline, reason)
	}
}
