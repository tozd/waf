package waf_test

import (
	"testing"

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
