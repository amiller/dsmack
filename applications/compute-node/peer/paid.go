package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sync"
	"time"

	payments "dsmack-payments"
)

func paidMeter() *payments.Meter {
	raw := os.Getenv("PAYMENTS_CONFIG")
	if raw == "" {
		return nil
	}
	var cfg payments.Config
	must(json.Unmarshal([]byte(raw), &cfg))
	m, e := payments.New(cfg)
	must(e)
	return m
}

// A paid purchase buys a single job. Finalizing either success or cutoff prevents
// reopening its allowance, even when a new job ID is presented concurrently.
type paidJob struct {
	meter   *payments.Meter
	grant   payments.Grant
	start   time.Time
	left    int64
	publish func(payments.SignedReceipt) error
	mu      sync.Mutex
	done    chan struct{}
	stopped chan struct{}
	path    string
	stop    func()
	final   *payments.SignedReceipt
	err     error
}

func (p *paidJob) used() int64 {
	return min(p.left, max(1, int64(math.Ceil(time.Since(p.start).Seconds()))))
}
func (p *paidJob) begin() {
	p.done = make(chan struct{})
	p.stopped = make(chan struct{})
	go func() {
		defer close(p.stopped)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-p.done:
				return
			case <-tick.C:
				p.mu.Lock()
				r, e := p.meter.Receipt(p.grant, p.used(), false)
				if e == nil {
					e = p.publish(r)
				}
				p.mu.Unlock()
				if e != nil {
					fmt.Fprintln(os.Stderr, "paid receipt checkpoint:", e)
					if p.stop != nil {
						p.stop()
					}
					return
				}
			}
		}
	}()
}
func (p *paidJob) finish() (final *payments.SignedReceipt, err error) {
	if p.final != nil {
		return p.final, p.err
	}
	defer func() { p.err = err }()
	used := p.used()
	close(p.done)
	<-p.stopped
	p.mu.Lock()
	defer p.mu.Unlock()
	r, e := p.meter.Receipt(p.grant, used, true)
	if e != nil {
		return nil, e
	}
	p.final = &r
	// Keep the independently submittable original even if broker storage is down.
	if p.path != "" {
		f, err := os.OpenFile(p.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return &r, err
		}
		_, err = f.Write(append(canon(r), '\n'))
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return &r, err
		}
	}
	return &r, p.publish(r)
}
func paidReport(m *payments.Meter, registration map[string]any, legacy []byte, challenge string) ([]byte, error) {
	if _, e := hex.DecodeString(challenge); e != nil {
		return nil, e
	}
	return m.Report(registration["relay_peer"].(string), registration["manifest_sha256"].(string), registration["os_image_hash"].(string), legacy, challenge)
}
