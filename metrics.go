package waf

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"gitlab.com/tozd/go/errors"
)

const serverTimingHeader = "Server-Timing"

// DurationMeasurement is a measurement of a duration.
type DurationMeasurement struct {
	startTime time.Time

	Duration time.Duration
}

// Start records the start of the duration measurement.
//
// Not safe for concurrency.
func (d *DurationMeasurement) Start() *DurationMeasurement {
	if !d.startTime.IsZero() {
		panic(errors.New("duration measurement already started"))
	}
	d.startTime = time.Now()
	return d
}

// Stop computes the duration of the duration measurement.
//
// Not safe for concurrency.
func (d *DurationMeasurement) Stop() {
	if d.startTime.IsZero() {
		panic(errors.New("duration measurement not started"))
	}
	if d.Duration != 0 {
		panic(errors.New("duration measurement already stopped"))
	}
	d.Duration = time.Since(d.startTime)
}

// DurationMetric is a metric of a duration.
type DurationMetric struct {
	name string

	measurement *DurationMeasurement

	mu sync.Mutex
}

func (d *DurationMetric) Name() string {
	return d.name
}

func (d *DurationMetric) MarshalZerologObject(e *zerolog.Event) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// We use only really measured durations and not just started
	// (it is impossible to both start and end the measurement with 0 duration).
	if d.measurement != nil && d.measurement.Duration != 0 {
		e.Dur(d.name, d.measurement.Duration)
	}
}

func (d *DurationMetric) ServerTimingString() string {
	d.mu.Lock()
	defer d.mu.Unlock()

	// We use only really measured durations and not just started
	// (it is impossible to both start and end the measurement with 0 duration).
	if d.measurement != nil && d.measurement.Duration != 0 {
		// We want only millisecond precision to minimize side channels.
		return fmt.Sprintf("%s;dur=%d", d.name, d.measurement.Duration.Milliseconds())
	}

	return ""
}

// Start starts a duration measurement.
//
// Can be called only once per metric.
func (d *DurationMetric) Start() *DurationMeasurement {
	m := new(DurationMeasurement)
	d.mu.Lock()
	// We do not allow starting an already started duration metrics.
	if d.measurement != nil {
		d.mu.Unlock()
		panic(errors.New("duration metric already started"))
	}
	d.measurement = m
	d.mu.Unlock()
	// We call Start outside of lock to minimize its impact on measurement.
	return m.Start()
}

// CounterMeasurement is a counter measurement.
type CounterMeasurement struct {
	Count int64
}

// Inc increases the counter by one.
//
// Not safe for concurrency.
func (c *CounterMeasurement) Inc() *CounterMeasurement {
	c.Count++
	return c
}

// Add increases the counter by n.
//
// Not safe for concurrency.
func (c *CounterMeasurement) Add(n int64) *CounterMeasurement {
	c.Count += n
	return c
}

// CounterMetric is a counter metric.
type CounterMetric struct {
	name string

	measurement *CounterMeasurement

	mu sync.Mutex
}

func (c *CounterMetric) Name() string {
	return c.name
}

func (c *CounterMetric) MarshalZerologObject(e *zerolog.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.measurement != nil {
		e.Int64(c.name, c.measurement.Count)
	}
}

func (c *CounterMetric) ServerTimingString() string {
	// Not supported.
	// TODO: Should we use non-standard key name?
	return ""
}

// Start starts a counter measurement.
//
// Can be called multiple times per metric with counter continuing.
func (c *CounterMetric) Start() *CounterMeasurement {
	c.mu.Lock()
	defer c.mu.Unlock()
	// We do allow starting an already started counter metrics.
	if c.measurement == nil {
		c.measurement = new(CounterMeasurement)
	}
	return c.measurement
}

// DurationsMetric is a metric of multiple durations.
type DurationsMetric struct {
	name string

	measurement []*DurationMeasurement

	mu sync.Mutex
}

func (d *DurationsMetric) Name() string {
	return d.name
}

func (d *DurationsMetric) MarshalZerologObject(e *zerolog.Event) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var min time.Duration = math.MaxInt64
	var max time.Duration
	var sum time.Duration
	var count int

	for _, m := range d.measurement {
		// We use only really measured durations and not just started
		// (it is impossible to both start and end the measurement with 0 duration).
		if m.Duration != 0 {
			if min > m.Duration {
				min = m.Duration
			}
			if max < m.Duration {
				max = m.Duration
			}
			sum += m.Duration
			count++
		}
	}

	if count == 0 {
		return
	}

	dict := zerolog.Dict()
	dict.Dur("min", min)
	dict.Dur("max", max)
	dict.Dur("dur", sum)
	dict.Int("count", count)
	dict.Dur("avg", time.Duration(int64(max-min)/int64(count)))
	e.Dict(d.name, dict)
}

func (d *DurationsMetric) ServerTimingString() string {
	// Not supported.
	// TODO: Should we support non-standard key name? Or use average? Or return multiple durations, one for min, avg, and max?
	return ""
}

// Start starts a new duration measurement.
//
// Can be called multiple times per metric with each call returning a new measurement.
func (d *DurationsMetric) Start() *DurationMeasurement {
	m := new(DurationMeasurement)
	d.mu.Lock()
	d.measurement = append(d.measurement, m)
	d.mu.Unlock()
	// We call Start outside of lock to minimize its impact on measurement.
	return m.Start()
}

// DurationMeasurement is a counter measurement within a duration.
type DurationCounterMeasurement struct {
	startTime time.Time

	Duration time.Duration
	Count    int64
}

// Start records the start of the duration measurement.
//
// Not safe for concurrency.
func (d *DurationCounterMeasurement) Start() *DurationCounterMeasurement {
	if !d.startTime.IsZero() {
		panic(errors.New("duration counter measurement already started"))
	}
	d.startTime = time.Now()
	return d
}

// Stop computes the duration of the duration measurement.
//
// Not safe for concurrency.
func (d *DurationCounterMeasurement) Stop() {
	if d.startTime.IsZero() {
		panic(errors.New("duration counter measurement not started"))
	}
	if d.Duration != 0 {
		panic(errors.New("duration counter measurement already stopped"))
	}
	d.Duration = time.Since(d.startTime)
}

// Inc increases the counter by one.
//
// Only possible after calling Start and before calling Stop.
//
// Not safe for concurrency.
func (d *DurationCounterMeasurement) Inc() *DurationCounterMeasurement {
	if d.startTime.IsZero() {
		panic(errors.New("duration counter measurement not started"))
	}
	if d.Duration != 0 {
		panic(errors.New("duration counter measurement already stopped"))
	}
	d.Count++
	return d
}

// Add increases the counter by n.
//
// Only possible after calling Start and before calling Stop.
//
// Not safe for concurrency.
func (d *DurationCounterMeasurement) Add(n int64) *DurationCounterMeasurement {
	if d.startTime.IsZero() {
		panic(errors.New("duration counter measurement not started"))
	}
	if d.Duration != 0 {
		panic(errors.New("duration counter measurement already stopped"))
	}
	d.Count += n
	return d
}

// DurationCounterMetric is a counter metric with a duration.
type DurationCounterMetric struct {
	name string

	measurement *DurationCounterMeasurement

	mu sync.Mutex
}

func (d *DurationCounterMetric) Name() string {
	return d.name
}

func (d *DurationCounterMetric) MarshalZerologObject(e *zerolog.Event) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// We use only really measured durations and not just started
	// (it is impossible to both start and end the measurement with 0 duration).
	if d.measurement != nil && d.measurement.Duration != 0 {
		dict := zerolog.Dict()
		dict.Dur("dur", d.measurement.Duration)
		dict.Int64("count", d.measurement.Count)
		dict.Float64("rate", float64(d.measurement.Count)/float64(d.measurement.Duration.Milliseconds()))
		e.Dict(d.name, dict)
	}
}

func (d *DurationCounterMetric) ServerTimingString() string {
	d.mu.Lock()
	defer d.mu.Unlock()

	// We use only really measured durations and not just started
	// (it is impossible to both start and end the measurement with 0 duration).
	if d.measurement != nil && d.measurement.Duration != 0 {
		// We want only millisecond precision to minimize any side channels.
		return fmt.Sprintf("%s;dur=%d", d.name, d.measurement.Duration.Milliseconds())
	}

	return ""
}

// Start starts a duration counter measurement.
//
// Can be called only once per metric.
func (d *DurationCounterMetric) Start() *DurationCounterMeasurement {
	m := new(DurationCounterMeasurement)
	d.mu.Lock()
	// We do not allow starting an already started duration metrics.
	if d.measurement != nil {
		d.mu.Unlock()
		panic(errors.New("duration counter metric already started"))
	}
	d.measurement = m
	d.mu.Unlock()
	// We call Start outside of lock to minimize its impact on measurement.
	return m.Start()
}

type metric interface {
	// All metrics also implement Start() method.
	Name() string
	zerolog.LogObjectMarshaler
	ServerTimingString() string
}

// Metrics is a set of metrics.
//
// Only one metric can exist with a given name.
type Metrics struct {
	metrics map[string]metric
	mu      sync.Mutex
}

// NewMetrics returns new initialized Metrics.
func NewMetrics() *Metrics {
	return &Metrics{
		metrics: map[string]metric{},
		mu:      sync.Mutex{},
	}
}

// TODO: Return same type as mt type.
//       See: https://github.com/golang/go/issues/49085

// Add adds a metric to the set of metrics.
//
// If an existing metric has the same name,
// nothing is added if the existing metric is equal
// to the metric being added. Otherwise Add panics.
func (m *Metrics) Add(mt metric) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if t, ok := m.metrics[mt.Name()]; ok {
		if t == mt {
			return
		}
		errE := errors.New("duplicate metric")
		errors.Details(errE)["name"] = mt.Name()
		panic(errE)
	}

	m.metrics[mt.Name()] = mt
}

// Duration returns a new duration metric.
//
// If called with the name of an existing duration metric,
// that duration metric is returned instead.
func (m *Metrics) Duration(name string) *DurationMetric {
	m.mu.Lock()
	defer m.mu.Unlock()

	if d, ok := m.metrics[name]; ok {
		if dm, ok := d.(*DurationMetric); ok {
			return dm
		}
		errE := errors.New("duplicate metric")
		errors.Details(errE)["name"] = name
		panic(errE)
	}

	dm := &DurationMetric{name: name} //nolint:exhaustruct
	m.metrics[name] = dm
	return dm
}

// Counter returns a new counter metric.
//
// If called with the name of an existing counter metric,
// that counter metric is returned instead.
func (m *Metrics) Counter(name string) *CounterMetric {
	m.mu.Lock()
	defer m.mu.Unlock()

	if c, ok := m.metrics[name]; ok {
		if cm, ok := c.(*CounterMetric); ok {
			return cm
		}
		errE := errors.New("duplicate metric")
		errors.Details(errE)["name"] = name
		panic(errE)
	}

	cm := &CounterMetric{name: name} //nolint:exhaustruct
	m.metrics[name] = cm
	return cm
}

// Durations returns a new durations metric.
//
// If called with the name of an existing durations metric,
// that durations metric is returned instead.
func (m *Metrics) Durations(name string) *DurationsMetric {
	m.mu.Lock()
	defer m.mu.Unlock()

	if d, ok := m.metrics[name]; ok {
		if dm, ok := d.(*DurationsMetric); ok {
			return dm
		}
		errE := errors.New("duplicate metric")
		errors.Details(errE)["name"] = name
		panic(errE)
	}

	dm := &DurationsMetric{name: name} //nolint:exhaustruct
	m.metrics[name] = dm
	return dm
}

// DurationCounter returns a new duration counter metric.
//
// If called with the name of an existing duration counter metric,
// that duration counter metric is returned instead.
func (m *Metrics) DurationCounter(name string) *DurationCounterMetric {
	m.mu.Lock()
	defer m.mu.Unlock()

	if d, ok := m.metrics[name]; ok {
		if dm, ok := d.(*DurationCounterMetric); ok {
			return dm
		}
		errE := errors.New("duplicate metric")
		errors.Details(errE)["name"] = name
		panic(errE)
	}

	dm := &DurationCounterMetric{name: name} //nolint:exhaustruct
	m.metrics[name] = dm
	return dm
}

func (m *Metrics) MarshalZerologObject(e *zerolog.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.metrics) == 0 {
		return
	}

	// We sort names so that we log them always in the same order to make logs reproducible.
	metrics := make([]string, 0, len(m.metrics))
	for name := range m.metrics {
		metrics = append(metrics, name)
	}
	sort.Strings(metrics)

	for _, name := range metrics {
		m.metrics[name].MarshalZerologObject(e)
	}
}

func (m *Metrics) ServerTimingString() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	// We sort names so that we log them always in the same order to make headers reproducible.
	metrics := make([]string, 0, len(m.metrics))
	for name := range m.metrics {
		metrics = append(metrics, name)
	}
	sort.Strings(metrics)

	parts := make([]string, 0, len(m.metrics))
	for _, name := range metrics {
		part := m.metrics[name].ServerTimingString()
		if part != "" {
			parts = append(parts, part)
		}
	}

	return strings.Join(parts, ",")
}

type logOnlyDurationMetric struct {
	name     string
	duration time.Duration
}

func (d *logOnlyDurationMetric) Name() string {
	return d.name
}

func (d *logOnlyDurationMetric) MarshalZerologObject(e *zerolog.Event) {
	e.Dur(d.name, d.duration)
}

func (d *logOnlyDurationMetric) ServerTimingString() string {
	return ""
}
