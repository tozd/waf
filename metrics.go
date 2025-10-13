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

const (
	// MetricCompress is the name of the metric which measures the time it takes to compress a response.
	MetricCompress = "c"

	// MetricJSONMarshal is the name of the metric which measures the time it takes to marshal a JSON response.
	MetricJSONMarshal = "j"

	// MetricTotal is the name of the metric which measures the total time it takes to process a request.
	MetricTotal = "t"
)

const serverTimingHeader = "Server-Timing"

// DurationMeasurement is a measurement of a duration.
type DurationMeasurement struct {
	startTime time.Time

	Discarded bool
	Duration  time.Duration
}

// Start records the start of the duration.
func (d *DurationMeasurement) Start() *DurationMeasurement {
	if d == nil || d.Discarded {
		return d
	}
	if !d.startTime.IsZero() {
		panic(errors.New("duration measurement already started"))
	}
	d.startTime = time.Now()
	return d
}

// Stop computes the duration.
func (d *DurationMeasurement) Stop() *DurationMeasurement {
	if d == nil || d.Discarded {
		return d
	}
	if d.startTime.IsZero() {
		panic(errors.New("duration measurement not started"))
	}
	if d.Duration != 0 {
		panic(errors.New("duration measurement already stopped"))
	}
	d.Duration = time.Since(d.startTime)
	return d
}

// Discard discards the measurement.
//
// Any future calls to measurement methods are ignored.
func (d *DurationMeasurement) Discard() *DurationMeasurement {
	if d == nil {
		return d
	}
	d.Discarded = true
	return d
}

// DurationMetric is a metric of a duration.
type DurationMetric struct {
	name      string
	startTime time.Time

	Discarded bool
	Duration  time.Duration
}

// Name returns the name of the metric.
func (d *DurationMetric) Name() string {
	if d == nil {
		return ""
	}
	return d.name
}

// MarshalZerologObject implements the [zerolog.LogObjectMarshaler] interface for DurationMetric.
func (d *DurationMetric) MarshalZerologObject(e *zerolog.Event) {
	// We use only really measured durations and not just started
	// (it is impossible to both start and end the measurement with 0 duration).
	if d == nil || d.Discarded || d.Duration == 0 {
		return
	}

	e.Dur(d.name, d.Duration)
}

// ServerTimingString returns the Server-Timing header value for the metric.
func (d *DurationMetric) ServerTimingString() string {
	// We use only really measured durations and not just started
	// (it is impossible to both start and end the measurement with 0 duration).
	if d == nil || d.Discarded || d.Duration == 0 {
		return ""
	}

	// We want only millisecond precision to minimize any side channels.
	return fmt.Sprintf("%s;dur=%d", d.name, d.Duration.Milliseconds())
}

// Start records the start of the duration.
//
// Can be called only once per metric.
func (d *DurationMetric) Start() *DurationMetric {
	if d == nil || d.Discarded {
		return d
	}
	if !d.startTime.IsZero() {
		panic(errors.New("duration metric already started"))
	}
	d.startTime = time.Now()
	return d
}

// Stop computes the duration.
func (d *DurationMetric) Stop() *DurationMetric {
	if d == nil || d.Discarded {
		return d
	}
	if d.startTime.IsZero() {
		panic(errors.New("duration metric not started"))
	}
	if d.Duration != 0 {
		panic(errors.New("duration metric already stopped"))
	}
	d.Duration = time.Since(d.startTime)
	return d
}

// Discard discards the metric.
//
// Any future calls to metric methods are ignored.
func (d *DurationMetric) Discard() *DurationMetric {
	if d == nil {
		return d
	}
	d.Discarded = true
	return d
}

// CounterMetric is a counter metric.
type CounterMetric struct {
	name string

	Discarded bool
	Count     int64
}

// Name returns the name of the metric.
func (c *CounterMetric) Name() string {
	if c == nil {
		return ""
	}
	return c.name
}

// MarshalZerologObject implements the [zerolog.LogObjectMarshaler] interface for CounterMetric.
func (c *CounterMetric) MarshalZerologObject(e *zerolog.Event) {
	if c == nil || c.Discarded {
		return
	}

	e.Int64(c.name, c.Count)
}

// ServerTimingString returns the Server-Timing header value for the metric.
func (c *CounterMetric) ServerTimingString() string {
	// Not supported.
	// TODO: Should we use non-standard key name?
	return ""
}

// Inc increases the counter by one.
func (c *CounterMetric) Inc() *CounterMetric {
	if c == nil || c.Discarded {
		return c
	}
	c.Count++
	return c
}

// Add increases the counter by n.
func (c *CounterMetric) Add(n int64) *CounterMetric {
	if c == nil || c.Discarded {
		return c
	}
	c.Count += n
	return c
}

// Discard discards the metric.
//
// Any future calls to metric methods are ignored.
func (c *CounterMetric) Discard() *CounterMetric {
	if c == nil {
		return c
	}
	c.Discarded = true
	return c
}

// DurationsMetric is a metric of multiple durations.
type DurationsMetric struct {
	name string

	Discarded bool
	Durations []*DurationMeasurement

	// Lock for appending to Durations.
	mu sync.Mutex
}

// Name returns the name of the metric.
func (d *DurationsMetric) Name() string {
	if d == nil {
		return ""
	}
	return d.name
}

// MarshalZerologObject implements the [zerolog.LogObjectMarshaler] interface for DurationsMetric.
func (d *DurationsMetric) MarshalZerologObject(e *zerolog.Event) {
	if d == nil || d.Discarded {
		return
	}

	var minDuration time.Duration = math.MaxInt64
	var maxDuration time.Duration
	var sum time.Duration
	var count int

	for _, m := range d.Durations {
		// We use only really measured durations and not just started
		// (it is impossible to both start and end the measurement with 0 duration).
		if m.Discarded || m.Duration == 0 {
			continue
		}

		if minDuration > m.Duration {
			minDuration = m.Duration
		}
		if maxDuration < m.Duration {
			maxDuration = m.Duration
		}
		sum += m.Duration
		count++
	}

	if count == 0 {
		return
	}

	dict := zerolog.Dict()
	// We add fields in the alphabetical order to match Go JSON marshaling order.
	dict.Dur("avg", time.Duration(int64(maxDuration-minDuration)/int64(count)))
	dict.Int("count", count)
	dict.Dur("dur", sum)
	dict.Dur("max", maxDuration)
	dict.Dur("min", minDuration)
	e.Dict(d.name, dict)
}

// ServerTimingString returns the Server-Timing header value for the metric.
func (d *DurationsMetric) ServerTimingString() string {
	// Not supported.
	// TODO: Should we support non-standard key name? Or use average? Or return multiple durations, one for min, avg, and max?
	return ""
}

// Start starts a new duration measurement.
//
// Can be called multiple times per metric with each call returning a new measurement.
func (d *DurationsMetric) Start() *DurationMeasurement {
	if d == nil {
		return nil
	}
	m := new(DurationMeasurement)
	if d.Discarded {
		m.Discarded = true
		return m
	}
	d.mu.Lock()
	d.Durations = append(d.Durations, m)
	d.mu.Unlock()
	// We call Start outside of lock to minimize its impact on measurement.
	return m.Start()
}

// Discard discards the metric.
//
// Any future calls to Start return an already discarded duration measurement.
func (d *DurationsMetric) Discard() *DurationsMetric {
	if d == nil {
		return d
	}
	d.Discarded = true
	return d
}

// DurationCounterMetric is a counter metric with a duration.
type DurationCounterMetric struct {
	name      string
	startTime time.Time

	Discarded bool
	Duration  time.Duration
	Count     int64
}

// Name returns the name of the metric.
func (d *DurationCounterMetric) Name() string {
	if d == nil {
		return ""
	}
	return d.name
}

// MarshalZerologObject implements the [zerolog.LogObjectMarshaler] interface for DurationCounterMetric.
func (d *DurationCounterMetric) MarshalZerologObject(e *zerolog.Event) {
	// We use only really measured durations and not just started
	// (it is impossible to both start and end the measurement with 0 duration).
	if d == nil || d.Discarded || d.Duration == 0 {
		return
	}

	dict := zerolog.Dict()
	// We add fields in the alphabetical order to match Go JSON marshaling order.
	dict.Int64("count", d.Count)
	dict.Dur("dur", d.Duration)
	dict.Float64("rate", float64(d.Count)/d.Duration.Seconds())
	e.Dict(d.name, dict)
}

// ServerTimingString returns the Server-Timing header value for the metric.
func (d *DurationCounterMetric) ServerTimingString() string {
	// We use only really measured durations and not just started
	// (it is impossible to both start and end the measurement with 0 duration).
	if d == nil || d.Discarded || d.Duration == 0 {
		return ""
	}

	// We want only millisecond precision to minimize any side channels.
	return fmt.Sprintf("%s;dur=%d", d.name, d.Duration.Milliseconds())
}

// Start records the start of the duration.
//
// Can be called only once per metric.
func (d *DurationCounterMetric) Start() *DurationCounterMetric {
	if d == nil || d.Discarded {
		return d
	}
	if !d.startTime.IsZero() {
		panic(errors.New("duration counter metric already started"))
	}
	d.startTime = time.Now()
	return d
}

// Stop computes the duration.
func (d *DurationCounterMetric) Stop() *DurationCounterMetric {
	if d == nil || d.Discarded {
		return d
	}
	if d.startTime.IsZero() {
		panic(errors.New("duration counter metric not started"))
	}
	if d.Duration != 0 {
		panic(errors.New("duration counter metric already stopped"))
	}
	d.Duration = time.Since(d.startTime)
	return d
}

// Inc increases the counter by one.
//
// Only possible after calling Start and before calling Stop.
func (d *DurationCounterMetric) Inc() *DurationCounterMetric {
	if d == nil || d.Discarded {
		return d
	}
	if d.startTime.IsZero() {
		panic(errors.New("duration counter metric not started"))
	}
	if d.Duration != 0 {
		panic(errors.New("duration counter metric already stopped"))
	}
	d.Count++
	return d
}

// Add increases the counter by n.
//
// Only possible after calling Start and before calling Stop.
func (d *DurationCounterMetric) Add(n int64) *DurationCounterMetric {
	if d == nil || d.Discarded {
		return d
	}
	if d.startTime.IsZero() {
		panic(errors.New("duration counter metric not started"))
	}
	if d.Duration != 0 {
		panic(errors.New("duration counter metric already stopped"))
	}
	d.Count += n
	return d
}

// Discard discards the metric.
//
// Any future calls to metric methods are ignored.
func (d *DurationCounterMetric) Discard() *DurationCounterMetric {
	if d == nil {
		return d
	}
	d.Discarded = true
	return d
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
	if m == nil {
		return
	}

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
	if m == nil {
		return nil
	}

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
	if m == nil {
		return nil
	}

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
	if m == nil {
		return nil
	}

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
	if m == nil {
		return nil
	}

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

// MarshalZerologObject implements the [zerolog.LogObjectMarshaler] interface for Metrics.
func (m *Metrics) MarshalZerologObject(e *zerolog.Event) {
	if m == nil {
		return
	}

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

// ServerTimingString returns the Server-Timing header value for the metrics.
func (m *Metrics) ServerTimingString() string {
	if m == nil {
		return ""
	}

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
