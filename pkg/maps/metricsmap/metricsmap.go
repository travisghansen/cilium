// Copyright 2016-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metricsmap

import (
	"context"
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/ebpfutils"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"

	"github.com/cilium/ebpf"

	"github.com/prometheus/client_golang/prometheus"
)

// MetricsMap interface represents a metrics map, and can be reused to implement
// mock maps for unit tests.
type MetricsMap interface {
	IterateWithCallback(ebpfutils.IterateCallback) error
}

type metricsMap struct {
	*ebpfutils.Map
}

var (
	// Metrics is the bpf metrics map
	Metrics metricsMap
	log     = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-metrics")
)

const (
	// MapName for metrics map.
	MapName = "cilium_metrics"
	// MaxEntries is the maximum number of keys that can be present in the
	// Metrics Map.
	//
	// Currently max. 2 bits of the Key.Dir member are used (unknown,
	// ingress or egress). Thus we can reduce from the theoretical max. size
	// of 2**16 (2 uint8) to 2**10 (1 uint8 + 2 bits).
	MaxEntries = 1024
	// dirIngress and dirEgress values should match with
	// METRIC_INGRESS, METRIC_EGRESS and METRIC_SERVICE
	// in bpf/lib/common.h
	dirUnknown = 0
	dirIngress = 1
	dirEgress  = 2
	dirService = 3
)

// direction is the metrics direction i.e ingress (to an endpoint),
// egress (from an endpoint) or service (NodePort service being accessed from
// outside or a ClusterIP service being accessed from inside the cluster).
// If it's none of the above, we return UNKNOWN direction.
var direction = map[uint8]string{
	dirUnknown: "UNKNOWN",
	dirIngress: "INGRESS",
	dirEgress:  "EGRESS",
	dirService: "SERVICE",
}

// Key must be in sync with struct metrics_key in <bpf/lib/common.h>
type Key struct {
	Reason   uint8     `align:"reason"`
	Dir      uint8     `align:"dir"`
	Reserved [3]uint16 `align:"reserved"`
}

// Value must be in sync with struct metrics_value in <bpf/lib/common.h>
type Value struct {
	Count uint64 `align:"count"`
	Bytes uint64 `align:"bytes"`
}

// Values is a slice of Values
type Values []Value

func (m metricsMap) IterateWithCallback(cb ebpfutils.IterateCallback) error {
	var key Key
	var values []Value

	return m.Map.IterateWithCallback(&key, &values, cb)
}

// String converts the value into a human readable string format
func (vs Values) String() string {
	sumCount, sumBytes := uint64(0), uint64(0)
	for _, v := range vs {
		sumCount += v.Count
		sumBytes += v.Bytes
	}
	return fmt.Sprintf("count:%d bytes:%d", sumCount, sumBytes)
}

// String converts the key into a human readable string format
func (k *Key) String() string {
	return fmt.Sprintf("reason:%d dir:%d", k.Reason, k.Dir)
}

// MetricDirection gets the direction in human readable string format
func MetricDirection(dir uint8) string {
	if desc, ok := direction[dir]; ok {
		return desc
	}
	return direction[dirUnknown]
}

// Direction gets the direction in human readable string format
func (k *Key) Direction() string {
	return MetricDirection(k.Dir)
}

// DropForwardReason gets the forwarded/dropped reason in human readable string format
func (k *Key) DropForwardReason() string {
	return monitorAPI.DropReason(k.Reason)
}

// String converts the value into a human readable string format
func (v *Value) String() string {
	return fmt.Sprintf("count:%d bytes:%d", v.Count, v.Bytes)
}

// IsDrop checks if the reason is drop or not.
func (k *Key) IsDrop() bool {
	return k.Reason == monitorAPI.DropInvalid || k.Reason >= monitorAPI.DropMin
}

func updateMetric(getCounter func() (prometheus.Counter, error), newValue float64) {
	counter, err := getCounter()
	if err != nil {
		log.WithError(err).Warn("Failed to update prometheus metrics")
		return
	}

	oldValue := metrics.GetCounterValue(counter)
	if newValue > oldValue {
		counter.Add(newValue - oldValue)
	}
}

// updatePrometheusMetrics checks the metricsmap key value pair
// and determines which prometheus metrics along with respective labels
// need to be updated.
func updatePrometheusMetrics(key *Key, values *[]Value) {
	// Metrics is a per-CPU map so we first need to aggregate the
	// different entries that make up a value.
	var packets, bytes uint64
	for _, value := range *values {
		packets += value.Count
		bytes += value.Bytes
	}

	updateMetric(func() (prometheus.Counter, error) {
		if key.IsDrop() {
			return metrics.DropCount.GetMetricWithLabelValues(key.DropForwardReason(), key.Direction())
		}
		return metrics.ForwardCount.GetMetricWithLabelValues(key.Direction())
	}, float64(packets))

	updateMetric(func() (prometheus.Counter, error) {
		if key.IsDrop() {
			return metrics.DropBytes.GetMetricWithLabelValues(key.DropForwardReason(), key.Direction())
		}
		return metrics.ForwardBytes.GetMetricWithLabelValues(key.Direction())
	}, float64(bytes))
}

// SyncMetricsMap is called periodically to sync off the metrics map by
// aggregating it into drops (by drop reason and direction) and
// forwards (by direction) with the prometheus server.
func SyncMetricsMap(ctx context.Context) error {
	cb := func(k, v interface{}) {
		key := k.(*Key)
		values := v.(*[]Value)
		updatePrometheusMetrics(key, values)
	}

	Metrics.IterateWithCallback(cb)

	return nil
}

func init() {
	Metrics.Map = ebpfutils.NewMap(&ebpf.MapSpec{
		Name:       MapName,
		Type:       ebpf.PerCPUHash,
		KeySize:    uint32(unsafe.Sizeof(Key{})),
		ValueSize:  uint32(unsafe.Sizeof(Value{})),
		MaxEntries: MaxEntries,
	})
}
