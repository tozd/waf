package waf_test

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"gitlab.com/tozd/waf"
)

func TestMetrics(t *testing.T) {
	t.Parallel()

	metrics := (*waf.Metrics)(nil)

	// There is a similar set of calls in TestMetricsMiddleware.
	metrics.Counter("counter").Add(40)
	metrics.Counter("discardedCounter").Inc().Discard()
	metrics.Duration("duration").Start().Stop()
	metrics.Duration("foreverDuration").Start()
	metrics.Duration("discardedDuration1").Start().Discard().Stop()
	metrics.Duration("discardedDuration2").Start().Stop().Discard()
	ds := metrics.Durations("durations")
	ds.Start().Stop()
	ds.Start().Stop()
	ds = metrics.Durations("discardedDurations")
	ds.Start().Discard().Stop()
	ds.Start().Stop().Discard()
	dc := metrics.DurationCounter("dc").Start().Add(43)
	metrics.DurationCounter("discardedDc1").Start().Add(32).Discard().Stop()
	metrics.DurationCounter("discardedDc2").Start().Add(33).Stop().Discard()
	metrics.DurationCounter("foreverDc").Start().Add(43)
	metrics.Counter("counter").Inc()
	metrics.DurationCounter("dc").Inc()
	metrics.Duration("trailer").Start().Stop()
	dc.Stop()
}

func TestMetricNames(t *testing.T) {
	t.Parallel()

	// Nil receivers return empty string.
	assert.Equal(t, "", (*waf.DurationMetric)(nil).Name())
	assert.Equal(t, "", (*waf.CounterMetric)(nil).Name())
	assert.Equal(t, "", (*waf.DurationsMetric)(nil).Name())
	assert.Equal(t, "", (*waf.DurationCounterMetric)(nil).Name())

	// Named metrics return their name.
	m := waf.NewMetrics()
	assert.Equal(t, "dur", m.Duration("dur").Name())
	assert.Equal(t, "cnt", m.Counter("cnt").Name())
	assert.Equal(t, "durs", m.Durations("durs").Name())
	assert.Equal(t, "dc", m.DurationCounter("dc").Name())
}

func TestDurationsMetricDiscard(t *testing.T) {
	t.Parallel()

	// Nil receiver returns nil.
	var nilDs *waf.DurationsMetric
	assert.Nil(t, nilDs.Discard())

	m := waf.NewMetrics()
	ds := m.Durations("test")

	assert.False(t, ds.Discarded)
	ds.Discard()
	assert.True(t, ds.Discarded)

	// After discarding, Start returns a discarded measurement.
	measurement := ds.Start()
	assert.True(t, measurement.Discarded)
}

func TestMetricsAdd(t *testing.T) {
	t.Parallel()

	dm := &waf.DurationMetric{}

	// Nil Metrics.Add is a no-op.
	var nilMetrics *waf.Metrics
	assert.NotPanics(t, func() { nilMetrics.Add(dm) })

	m := waf.NewMetrics()

	// Add a new metric.
	assert.NotPanics(t, func() { m.Add(dm) })

	// Add the same pointer again — no-op.
	assert.NotPanics(t, func() { m.Add(dm) })

	// Add a different pointer with the same name — panics.
	dm2 := &waf.DurationMetric{}
	assert.Panics(t, func() { m.Add(dm2) })
}

func TestDurationMeasurementDiscarded(t *testing.T) {
	t.Parallel()

	// Start on a discarded measurement is a no-op.
	m := &waf.DurationMeasurement{}
	m.Discard()
	result := m.Start()
	assert.Equal(t, m, result)
}

func TestMetricsReturnExisting(t *testing.T) {
	t.Parallel()

	m := waf.NewMetrics()

	// Calling Duration/Counter/Durations/DurationCounter twice returns the same metric.
	d1 := m.Duration("d")
	d2 := m.Duration("d")
	assert.Equal(t, d1, d2)

	c1 := m.Counter("c")
	c2 := m.Counter("c")
	assert.Equal(t, c1, c2)

	ds1 := m.Durations("ds")
	ds2 := m.Durations("ds")
	assert.Equal(t, ds1, ds2)

	dc1 := m.DurationCounter("dc")
	dc2 := m.DurationCounter("dc")
	assert.Equal(t, dc1, dc2)
}

func TestMetricsServerTimingStringEmpty(t *testing.T) {
	t.Parallel()

	// Non-nil but empty Metrics returns empty string.
	m := waf.NewMetrics()
	assert.Equal(t, "", m.ServerTimingString())

	// Counter-only Metrics: ServerTimingString always returns "" for counters.
	m2 := waf.NewMetrics()
	m2.Counter("cnt").Inc()
	assert.Equal(t, "", m2.ServerTimingString())
}

func TestDurationMeasurementPanics(t *testing.T) {
	t.Parallel()

	m := waf.NewMetrics()
	ds := m.Durations("test")

	// Start twice panics.
	measurement := ds.Start()
	assert.Panics(t, func() { measurement.Start() })
	measurement.Stop() //nolint:errcheck

	// Stop without start panics.
	m2 := &waf.DurationMeasurement{}
	assert.Panics(t, func() { m2.Stop() })

	// Stop twice panics.
	m3 := &waf.DurationMeasurement{}
	m3.Start()
	m3.Stop() //nolint:errcheck
	assert.Panics(t, func() { m3.Stop() })
}

func TestDurationMetricPanics(t *testing.T) {
	t.Parallel()

	// Start twice panics.
	d := waf.NewMetrics().Duration("d")
	d.Start()
	assert.Panics(t, func() { d.Start() })

	// Stop without start panics.
	assert.Panics(t, func() { waf.NewMetrics().Duration("d").Stop() })

	// Stop twice panics.
	d2 := waf.NewMetrics().Duration("d")
	d2.Start()
	d2.Stop() //nolint:errcheck
	assert.Panics(t, func() { d2.Stop() })
}

func TestDurationCounterMetricPanics(t *testing.T) {
	t.Parallel()

	newDC := func() *waf.DurationCounterMetric {
		return waf.NewMetrics().DurationCounter("dc")
	}

	// Start twice panics.
	dc := newDC()
	dc.Start()
	assert.Panics(t, func() { dc.Start() })

	// Stop without start panics.
	assert.Panics(t, func() { newDC().Stop() })

	// Stop twice panics.
	dc2 := newDC()
	dc2.Start()
	dc2.Stop() //nolint:errcheck
	assert.Panics(t, func() { dc2.Stop() })

	// Inc without start panics.
	assert.Panics(t, func() { newDC().Inc() })

	// Add without start panics.
	assert.Panics(t, func() { newDC().Add(1) })

	// Inc after stop panics.
	dc3 := newDC()
	dc3.Start()
	dc3.Stop() //nolint:errcheck
	assert.Panics(t, func() { dc3.Inc() })

	// Add after stop panics.
	dc4 := newDC()
	dc4.Start()
	dc4.Stop() //nolint:errcheck
	assert.Panics(t, func() { dc4.Add(1) })
}

func TestMetricsDuplicateTypePanic(t *testing.T) {
	t.Parallel()

	// Counter then Duration with same name panics.
	m := waf.NewMetrics()
	m.Counter("x")
	assert.Panics(t, func() { m.Duration("x") })

	// Duration then Counter with same name panics.
	m2 := waf.NewMetrics()
	m2.Duration("y")
	assert.Panics(t, func() { m2.Counter("y") })

	// Counter then Durations with same name panics.
	m3 := waf.NewMetrics()
	m3.Counter("z")
	assert.Panics(t, func() { m3.Durations("z") })

	// Counter then DurationCounter with same name panics.
	m4 := waf.NewMetrics()
	m4.Counter("w")
	assert.Panics(t, func() { m4.DurationCounter("w") })
}

func TestMetricsMarshalZerologObjectEmpty(t *testing.T) {
	t.Parallel()

	// Non-nil but empty Metrics returns early without writing any fields into the dict.
	m := waf.NewMetrics()
	buf := &bytes.Buffer{}
	l := zerolog.New(buf)
	l.Log().Object("m", m).Msg("")
	assert.Equal(t, `{"m":{}}`+"\n", buf.String())
}
