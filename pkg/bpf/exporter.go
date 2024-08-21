/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package bpf

import (
	"fmt"
	"os"
	"runtime"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jaypipes/ghw"
	"github.com/sustainable-computing-io/kepler/pkg/config"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
)

type exporter struct {
	bpfObjects keplerObjects

	schedSwitchLink link.Link
	irqLink         link.Link
	pageWriteLink   link.Link
	pageReadLink    link.Link

	perfEvents *hardwarePerfEvents

	enabledHardwareCounters sets.Set[string]
	enabledSoftwareCounters sets.Set[string]
}

func NewExporter() (Exporter, error) {
	e := &exporter{
		enabledHardwareCounters: sets.New[string](),
		enabledSoftwareCounters: sets.New[string](),
	}
	err := e.attach()
	if err != nil {
		e.Detach()
	}
	return e, err
}

func (e *exporter) SupportedMetrics() SupportedMetrics {
	return SupportedMetrics{
		HardwareCounters: e.enabledHardwareCounters.Clone(),
		SoftwareCounters: e.enabledSoftwareCounters.Clone(),
	}
}

func (e *exporter) attach() error {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("error removing memlock: %v", err)
	}

	// Load eBPF Specs
	specs, err := loadKepler()
	if err != nil {
		return fmt.Errorf("error loading eBPF specs: %v", err)
	}

	// Adjust map sizes to the number of available CPUs
	numCPU := getCPUCores()
	klog.Infof("Number of CPUs: %d", numCPU)
	for _, m := range specs.Maps {
		// Only resize maps that have a MaxEntries of NUM_CPUS constant
		if m.MaxEntries == 128 {
			m.MaxEntries = uint32(numCPU)
		}
	}

	// Set program global variables
	err = specs.RewriteConstants(map[string]interface{}{
		"SAMPLE_RATE": int32(config.BPFSampleRate),
	})
	if err != nil {
		return fmt.Errorf("error rewriting program constants: %v", err)
	}

	// Load the eBPF program(s)
	if err := specs.LoadAndAssign(&e.bpfObjects, nil); err != nil {
		return fmt.Errorf("error loading eBPF objects: %v", err)
	}

	// Attach the eBPF program(s)
	e.schedSwitchLink, err = link.AttachTracing(link.TracingOptions{
		Program:    e.bpfObjects.KeplerSchedSwitchTrace,
		AttachType: ebpf.AttachTraceRawTp,
	})
	if err != nil {
		return fmt.Errorf("error attaching sched_switch tracepoint: %v", err)
	}
	e.enabledSoftwareCounters[config.CPUTime] = struct{}{}

	if config.ExposeIRQCounterMetrics {
		e.irqLink, err = link.AttachTracing(link.TracingOptions{
			Program:    e.bpfObjects.KeplerIrqTrace,
			AttachType: ebpf.AttachTraceRawTp,
		})
		if err != nil {
			return fmt.Errorf("could not attach irq/softirq_entry: %w", err)
		}
		e.enabledSoftwareCounters[config.IRQNetTXLabel] = struct{}{}
		e.enabledSoftwareCounters[config.IRQNetRXLabel] = struct{}{}
		e.enabledSoftwareCounters[config.IRQBlockLabel] = struct{}{}
	}

	group := "writeback"
	name := "writeback_dirty_page"
	if _, err := os.Stat("/sys/kernel/debug/tracing/events/writeback/writeback_dirty_folio"); err == nil {
		name = "writeback_dirty_folio"
	}
	e.pageWriteLink, err = link.Tracepoint(group, name, e.bpfObjects.KeplerWritePageTrace, nil)
	if err != nil {
		klog.Warningf("failed to attach tp/%s/%s: %v. Kepler will not collect page cache write events. This will affect the DRAM power model estimation on VMs.", group, name, err)
	} else {
		e.enabledSoftwareCounters[config.PageCacheHit] = struct{}{}
	}

	e.pageReadLink, err = link.AttachTracing(link.TracingOptions{
		Program:    e.bpfObjects.KeplerReadPageTrace,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		klog.Warningf("failed to attach fentry/mark_page_accessed: %v. Kepler will not collect page cache read events. This will affect the DRAM power model estimation on VMs.", err)
	} else if !e.enabledSoftwareCounters.Has(config.PageCacheHit) {
		e.enabledSoftwareCounters[config.PageCacheHit] = struct{}{}
	}

	// Return early if hardware counters are not enabled
	if !config.ExposeHardwareCounterMetrics {
		klog.Infof("Hardware counter metrics are disabled")
		return nil
	}

	e.perfEvents, err = createHardwarePerfEvents(
		e.bpfObjects.CpuInstructionsEventReader,
		e.bpfObjects.CpuCyclesEventReader,
		e.bpfObjects.CacheMissEventReader,
		numCPU,
	)
	if err != nil {
		return nil
	}
	e.enabledHardwareCounters[config.CPUCycle] = struct{}{}
	e.enabledHardwareCounters[config.CPUInstruction] = struct{}{}
	e.enabledHardwareCounters[config.CacheMiss] = struct{}{}

	return nil
}

func (e *exporter) Detach() {
	// Links
	if e.schedSwitchLink != nil {
		e.schedSwitchLink.Close()
		e.schedSwitchLink = nil
	}

	if e.irqLink != nil {
		e.irqLink.Close()
		e.irqLink = nil
	}

	if e.pageWriteLink != nil {
		e.pageWriteLink.Close()
		e.pageWriteLink = nil
	}

	if e.pageReadLink != nil {
		e.pageReadLink.Close()
		e.pageReadLink = nil
	}

	// Perf events
	e.perfEvents.close()
	e.perfEvents = nil

	// Objects
	e.bpfObjects.Close()
}

// Add these new structs to represent the new map data
type ExtrapolationData struct {
	TotalEvents   uint64
	SampledEvents uint64
	TotalCPUTime  map[uint32]uint64
}

func (e *exporter) CollectExtrapolationData() (*ExtrapolationData, error) {
	data := &ExtrapolationData{
		TotalCPUTime: make(map[uint32]uint64),
	}

	// Read and reset total_events
	var totalEvents uint64
	err := e.bpfObjects.TotalEvents.Lookup(uint32(0), &totalEvents)
	if err != nil {
		return nil, fmt.Errorf("failed to read total_events: %v", err)
	}
	data.TotalEvents = totalEvents

	// Reset total_events to 0
	err = e.bpfObjects.TotalEvents.Update(uint32(0), uint64(0), ebpf.UpdateAny)
	if err != nil {
		return nil, fmt.Errorf("failed to reset total_events: %v", err)
	}

	// Read and reset sampled_events
	var sampledEvents uint64
	err = e.bpfObjects.SampledEvents.Lookup(uint32(0), &sampledEvents)
	if err != nil {
		return nil, fmt.Errorf("failed to read sampled_events: %v", err)
	}
	data.SampledEvents = sampledEvents

	// Reset sampled_events to 0
	err = e.bpfObjects.SampledEvents.Update(uint32(0), uint64(0), ebpf.UpdateAny)
	if err != nil {
		return nil, fmt.Errorf("failed to reset sampled_events: %v", err)
	}

	// Read total_cpu_time and then clear it
	var key uint32
	var value uint64
	iterator := e.bpfObjects.TotalCpuTime.Iterate()
	for iterator.Next(&key, &value) {
		data.TotalCPUTime[key] = value
		// Delete each entry after reading it
		err := e.bpfObjects.TotalCpuTime.Delete(key)
		if err != nil {
			return nil, fmt.Errorf("error deleting entry from total_cpu_time: %v", err)
		}
	}
	if iterator.Err() != nil {
		return nil, fmt.Errorf("error iterating total_cpu_time: %v", iterator.Err())
	}
	klog.Infof("Collected extrapolation data: total_events=%d, sampled_events=%d, total_cpu_time=%v", data.TotalEvents, data.SampledEvents, data.TotalCPUTime)
	return data, nil
}

func (e *exporter) CollectProcesses() ([]ProcessMetrics, error) {
	start := time.Now()
	maxEntries := e.bpfObjects.Processes.MaxEntries()
	total := 0
	deleteKeys := make([]uint32, maxEntries)
	deleteValues := make([]ProcessMetrics, maxEntries)
	var cursor ebpf.MapBatchCursor
	// Collect extrapolation data
	extrapolationData, err := e.CollectExtrapolationData()
	if err != nil {
		klog.Errorf("failed to collect extrapolation data: %v", err)
		return nil, fmt.Errorf("failed to collect extrapolation data: %v", err)
	}

	for {
		count, err := e.bpfObjects.Processes.BatchLookupAndDelete(
			&cursor,
			deleteKeys,
			deleteValues,
			&ebpf.BatchOptions{},
		)
		total += count
		if err != nil {
			break
		}
	}

	// Calculate the global extrapolation factor
	extrapolationFactor := float64(extrapolationData.TotalEvents) / float64(extrapolationData.SampledEvents)

	// Extrapolate CPU time for each process
	for i := 0; i < total; i++ {
		pid := deleteValues[i].Pid
		sampledCPUTime := deleteValues[i].ProcessRunTime
		if totalCPUTime, ok := extrapolationData.TotalCPUTime[uint32(pid)]; ok {
			// Use both sampled CPU time and total CPU time for extrapolation
			sampledFraction := float64(sampledCPUTime) / float64(totalCPUTime)
			extrapolatedCPUTime := uint64(float64(totalCPUTime) * extrapolationFactor * sampledFraction)
			deleteValues[i].ProcessRunTime = extrapolatedCPUTime
			klog.Infof("Extrapolated CPU time for PID %d (sampled fraction %v factor %v): %v/%v -> %v", pid, sampledFraction, extrapolationFactor, sampledCPUTime, totalCPUTime, extrapolatedCPUTime)
		} else {
			// If we don't have total CPU time data, use the global extrapolation factor
			extrapolatedCPUTime := uint64(float64(sampledCPUTime) * extrapolationFactor)
			deleteValues[i].ProcessRunTime = extrapolatedCPUTime
			//klog.Warningf("No total CPU time data for PID %d, using global extrapolation: %v/%v", pid, extrapolatedCPUTime, sampledCPUTime)
		}
	}

	klog.V(5).Infof("collected and extrapolated %d process samples in %v", total, time.Since(start))
	return deleteValues[:total], nil
}

///////////////////////////////////////////////////////////////////////////
// utility functions

func unixOpenPerfEvent(typ, conf, cpuCores int) ([]int, error) {
	sysAttr := &unix.PerfEventAttr{
		Type:   uint32(typ),
		Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Config: uint64(conf),
	}
	fds := []int{}
	for i := 0; i < cpuCores; i++ {
		cloexecFlags := unix.PERF_FLAG_FD_CLOEXEC
		fd, err := unix.PerfEventOpen(sysAttr, -1, i, -1, cloexecFlags)
		if fd < 0 {
			return nil, fmt.Errorf("failed to open bpf perf event on cpu %d: %w", i, err)
		}
		fds = append(fds, fd)
	}
	return fds, nil
}

func unixClosePerfEvents(fds []int) {
	for _, fd := range fds {
		_ = unix.SetNonblock(fd, true)
		unix.Close(fd)
	}
}

func getCPUCores() int {
	cores := runtime.NumCPU()
	if cpu, err := ghw.CPU(); err == nil {
		// we need to get the number of all CPUs,
		// so if /proc/cpuinfo is available, we can get the number of all CPUs
		cores = int(cpu.TotalThreads)
	}
	return cores
}

type hardwarePerfEvents struct {
	cpuCyclesPerfEvents       []int
	cpuInstructionsPerfEvents []int
	cacheMissPerfEvents       []int
}

func (h *hardwarePerfEvents) close() {
	unixClosePerfEvents(h.cpuCyclesPerfEvents)
	unixClosePerfEvents(h.cpuInstructionsPerfEvents)
	unixClosePerfEvents(h.cacheMissPerfEvents)
}

// CreateHardwarePerfEvents creates perf events for CPU cycles, CPU instructions, and cache misses
// and updates the corresponding eBPF maps.
func createHardwarePerfEvents(cpuInstructionsMap, cpuCyclesMap, cacheMissMap *ebpf.Map, numCPU int) (*hardwarePerfEvents, error) {
	var err error
	events := &hardwarePerfEvents{
		cpuCyclesPerfEvents:       []int{},
		cpuInstructionsPerfEvents: []int{},
		cacheMissPerfEvents:       []int{},
	}
	defer func() {
		if err != nil {
			unixClosePerfEvents(events.cpuCyclesPerfEvents)
			unixClosePerfEvents(events.cpuInstructionsPerfEvents)
			unixClosePerfEvents(events.cacheMissPerfEvents)
		}
	}()

	// Create perf events and update each eBPF map
	events.cpuCyclesPerfEvents, err = unixOpenPerfEvent(unix.PERF_TYPE_HARDWARE, unix.PERF_COUNT_HW_CPU_CYCLES, numCPU)
	if err != nil {
		klog.Warning("Failed to open perf event for CPU cycles: ", err)
		return nil, err
	}

	events.cpuInstructionsPerfEvents, err = unixOpenPerfEvent(unix.PERF_TYPE_HARDWARE, unix.PERF_COUNT_HW_INSTRUCTIONS, numCPU)
	if err != nil {
		klog.Warning("Failed to open perf event for CPU instructions: ", err)
		return nil, err
	}

	events.cacheMissPerfEvents, err = unixOpenPerfEvent(unix.PERF_TYPE_HW_CACHE, unix.PERF_COUNT_HW_CACHE_MISSES, numCPU)
	if err != nil {
		klog.Warning("Failed to open perf event for cache misses: ", err)
		return nil, err
	}

	for i, fd := range events.cpuCyclesPerfEvents {
		if err = cpuCyclesMap.Update(uint32(i), uint32(fd), ebpf.UpdateAny); err != nil {
			klog.Warningf("Failed to update cpu_cycles_event_reader map: %v", err)
			return nil, err
		}
	}
	for i, fd := range events.cpuInstructionsPerfEvents {
		if err = cpuInstructionsMap.Update(uint32(i), uint32(fd), ebpf.UpdateAny); err != nil {
			klog.Warningf("Failed to update cpu_instructions_event_reader map: %v", err)
			return nil, err
		}
	}
	for i, fd := range events.cacheMissPerfEvents {
		if err = cacheMissMap.Update(uint32(i), uint32(fd), ebpf.UpdateAny); err != nil {
			klog.Warningf("Failed to update cache_miss_event_reader map: %v", err)
			return nil, err
		}
	}
	return events, nil
}
