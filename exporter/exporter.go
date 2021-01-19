package exporter

import (
	"fmt"
	"os"
	"log"
	"time"
	"strings"
	"net/http"
	"bufio"
	"encoding/json"
	"compress/gzip"
	"strconv"

	"github.com/ahas-sigs/kube-ebpf-exporter/config"
	"github.com/ahas-sigs/kube-ebpf-exporter/decoder"
	"github.com/iovisor/gobpf/bcc"
	"github.com/prometheus/client_golang/prometheus"
)
var (
	ahasSinkNodeCluster = "default"
	ahasSinkNodeZone = "default"
	ahasSinkNodeRegion = "default"
	ahasSinkNodeProvider = "default"
)
const (
	// Namespace to use for all metrics
	prometheusNamespace = "ebpf_exporter"
	ahasSinkRootPath = "/ahas-workspace/data/ahas/ahas-agent/ebpf-exporter/data"
)
const (
	ahasEventNodeKey = "ahas_event_node"
	ahasEventClusterKey = "ahas_event_cluster"
	ahasEventZoneKey = "ahas_event_zone"
	ahasEventRegionKey = "ahas_event_region"
	ahasEventProviderKey = "ahas_event_provider"
	ahasEventTimeKey = "ahas_event_time"
	ahasEventNameKey = "ahas_event_name"
	ahasEventValueKey = "ahas_event_value"
	ahasEventEbpfExporterStart = "ahas-sigs.cloudevents.kube-ebpf-exporter.start"
	ahasEventPath = "/ahas-workspace/data/ahas/ahas-agent/ebpf-exporter/event.dat"
)
const (
	ahasSinkNodeKey = "ahas_sink_node"
	ahasSinkClusterKey = "ahas_sink_cluster"
	ahasSinkZoneKey = "ahas_sink_zone"
	ahasSinkRegionKey = "ahas_sink_region"
	ahasSinkProviderKey = "ahas_sink_provider"
	ahasSinkTimeKey = "ahas_sink_time"
	ahasSinkNameKey = "ahas_sink_name"
	ahasSinkValueKey = "ahas_sink_value"
)

const (
	///only enable export, disable sink, default mode
	Sink_Mode_None = 0
	///enable sink and export
	Sink_Mode_Include_Export = 1
	///only enable sink, disable export
	Sink_Mode_Exclude_Export = 2
)

// Exporter is a ebpf_exporter instance implementing prometheus.Collector
type Exporter struct {
	nodeID              string
	nodeZone	    string
	nodeRegion	    string
	nodeProvider	    string
	nodeCluster         string
	sinkRoot            string
	sinkOutPutFile      string
	config              config.Config
	modules             map[string]*bcc.Module
	ksyms               map[uint64]string
	enabledProgramsDesc *prometheus.Desc
	programInfoDesc     *prometheus.Desc
	programTags         map[string]map[string]uint64
	descs               map[string]map[string]*prometheus.Desc
	decoders            *decoder.Set
}

// New creates a new exporter with the provided config
func New(nodeID string, config config.Config) *Exporter {

	enabledProgramsDesc := prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNamespace, "", "enabled_programs"),
		"The set of enabled programs",
		[]string{"name"},
		nil,
	)

	programInfoDesc := prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNamespace, "", "ebpf_programs"),
		"Info about ebpf programs",
		[]string{"program", "function", "tag"},
		nil,
	)

	nodeProvider := os.Getenv("AHAS_NODE_PROVIDER")
	if len(nodeProvider) > 1 {
		ahasSinkNodeProvider = nodeProvider
	}
	nodeRegion := os.Getenv("AHAS_NODE_REGION")
	if len(nodeRegion) > 1 {
		ahasSinkNodeRegion = nodeRegion
	}
	nodeZone := os.Getenv("AHAS_NODE_ZONE")
	if len(nodeZone) > 1 {
		ahasSinkNodeZone = nodeZone
	}
	nodeCluster := os.Getenv("AHAS_NODE_CLUSTER")
	if len(nodeCluster) > 1 {
		ahasSinkNodeCluster = nodeCluster
	}

	sinkRoot := fmt.Sprintf("%s/%s-%s-%s/node/%s",
		ahasSinkRootPath,
		ahasSinkNodeProvider,
		ahasSinkNodeRegion,
		ahasSinkNodeCluster,
		nodeID)
        _ = os.MkdirAll(sinkRoot, 0777)

	return &Exporter{
		nodeID:              nodeID,
		nodeZone:            ahasSinkNodeZone,
		nodeCluster:         ahasSinkNodeCluster,
		nodeRegion:          ahasSinkNodeRegion,
		nodeProvider:        ahasSinkNodeProvider,
		sinkRoot:            sinkRoot,
		sinkOutPutFile:      sinkRoot,
		config:              config,
		modules:             map[string]*bcc.Module{},
		ksyms:               map[uint64]string{},
		enabledProgramsDesc: enabledProgramsDesc,
		programInfoDesc:     programInfoDesc,
		programTags:         map[string]map[string]uint64{},
		descs:               map[string]map[string]*prometheus.Desc{},
		decoders:            decoder.NewSet(),
	}
}

// Attach injects eBPF into kernel and attaches necessary kprobes
func (e *Exporter) Attach() error {
	for _, program := range e.config.Programs {
		if _, ok := e.modules[program.Name]; ok {
			return fmt.Errorf("multiple programs with name %q", program.Name)
		}

		module := bcc.NewModule(program.Code, program.Cflags)
		if module == nil {
			return fmt.Errorf("error compiling module for program %q", program.Name)
		}

		tags, err := attach(module, program.Kprobes, program.Kretprobes, program.Tracepoints, program.RawTracepoints)

		if err != nil {
			return fmt.Errorf("failed to attach to program %q: %s", program.Name, err)
		}

		e.programTags[program.Name] = tags

		for _, perfEventConfig := range program.PerfEvents {
			target, err := module.LoadPerfEvent(perfEventConfig.Target)
			if err != nil {
				return fmt.Errorf("failed to load target %q in program %q: %s", perfEventConfig.Target, program.Name, err)
			}

			err = module.AttachPerfEvent(perfEventConfig.Type, perfEventConfig.Name, perfEventConfig.SamplePeriod, perfEventConfig.SampleFrequency, -1, -1, -1, target)
			if err != nil {
				return fmt.Errorf("failed to attach perf event %d:%d to %q in program %q: %s", perfEventConfig.Type, perfEventConfig.Name, perfEventConfig.Target, program.Name, err)
			}
		}

		e.modules[program.Name] = module
	}
	return nil
}

// Describe satisfies prometheus.Collector interface by sending descriptions
// for all metrics the exporter can possibly report
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	addDescs := func(programName string, name string, help string, labels []config.Label) {
		if _, ok := e.descs[programName][name]; !ok {
			labelNames := []string{}

			constLabels := prometheus.Labels{"node_id": e.nodeID}
			for _, label := range labels {
				labelNames = append(labelNames, label.Name)
			}

			e.descs[programName][name] = prometheus.NewDesc(prometheus.BuildFQName(prometheusNamespace, "", name), help, labelNames, constLabels)
		}

		ch <- e.descs[programName][name]
	}

	ch <- e.enabledProgramsDesc
	ch <- e.programInfoDesc

	for _, program := range e.config.Programs {
		if _, ok := e.descs[program.Name]; !ok {
			e.descs[program.Name] = map[string]*prometheus.Desc{}
		}

		for _, counter := range program.Metrics.Counters {
			addDescs(program.Name, counter.Name, counter.Help, counter.Labels)
		}

		for _, histogram := range program.Metrics.Histograms {
			addDescs(program.Name, histogram.Name, histogram.Help, histogram.Labels[0:len(histogram.Labels)-1])
		}
	}
}

// Collect satisfies prometheus.Collector interface and sends all metrics
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	for _, program := range e.config.Programs {
		ch <- prometheus.MustNewConstMetric(e.enabledProgramsDesc, prometheus.GaugeValue, 1, program.Name)
	}

	for program, tags := range e.programTags {
		for function, tag := range tags {
			ch <- prometheus.MustNewConstMetric(e.programInfoDesc, prometheus.GaugeValue, 1, program, function, fmt.Sprintf("%x", tag))
		}
	}

	e.collectCounters(ch)
	e.collectHistograms(ch)
}

// collectCounters sends all known counters to prometheus
func (e *Exporter) collectCounters(ch chan<- prometheus.Metric) {
	allSinkValues := []string{}
	for _, program := range e.config.Programs {
		for _, counter := range program.Metrics.Counters {
			tableValues, sinkValues, err := e.tableValues(e.modules[program.Name], counter.Table, counter.Labels)
			if err != nil {
				log.Printf("Error getting table %q values for metric %q of program %q: %s", counter.Table, counter.Name, program.Name, err)
				continue
			}

			desc := e.descs[program.Name][counter.Name]

			if counter.SinkMode != Sink_Mode_Exclude_Export {
				for _, metricValue := range tableValues {
					ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, metricValue.value, metricValue.labels...)
				}
			}
			if counter.SinkMode != Sink_Mode_None {
				allSinkValues = append(allSinkValues, sinkValues...)
			}
		}
		e.dumpSinkValues(allSinkValues)
	}
}

// collectHistograms sends all known historams to prometheus
func (e *Exporter) collectHistograms(ch chan<- prometheus.Metric) {
	for _, program := range e.config.Programs {
		for _, histogram := range program.Metrics.Histograms {
			skip := false

			histograms := map[string]histogramWithLabels{}

			tableValues, _, err := e.tableValues(e.modules[program.Name], histogram.Table, histogram.Labels)
			if err != nil {
				log.Printf("Error getting table %q values for metric %q of program %q: %s", histogram.Table, histogram.Name, program.Name, err)
				continue
			}

			// Taking the last label and using int as bucket delimiter, for example:
			//
			// Before:
			// * [sda, read, 1ms] -> 10
			// * [sda, read, 2ms] -> 2
			// * [sda, read, 4ms] -> 5
			//
			// After:
			// * [sda, read] -> {1ms -> 10, 2ms -> 2, 4ms -> 5}
			for _, metricValue := range tableValues {
				labels := metricValue.labels[0 : len(metricValue.labels)-1]

				key := fmt.Sprintf("%#v", labels)

				if _, ok := histograms[key]; !ok {
					histograms[key] = histogramWithLabels{
						labels:  labels,
						buckets: map[float64]uint64{},
					}
				}

				leUint, err := strconv.ParseUint(metricValue.labels[len(metricValue.labels)-1], 0, 64)
				if err != nil {
					log.Printf("Error parsing float value for bucket %#v in table %q of program %q: %s", metricValue.labels, histogram.Table, program.Name, err)
					skip = true
					break
				}

				histograms[key].buckets[float64(leUint)] = uint64(metricValue.value)
			}

			if skip {
				continue
			}

			desc := e.descs[program.Name][histogram.Name]

			for _, histogramSet := range histograms {
				buckets, count, sum, err := transformHistogram(histogramSet.buckets, histogram)
				if err != nil {
					log.Printf("Error transforming histogram for metric %q in program %q: %s", histogram.Name, program.Name, err)
					continue
				}

				// Sum is explicitly set to zero. We only take bucket values from
				// eBPF tables, which means we lose precision and cannot calculate
				// average values from histograms anyway.
				// Lack of sum also means we cannot have +Inf bucket, only some finite
				// value bucket, eBPF programs must cap bucket values to work with this.
				ch <- prometheus.MustNewConstHistogram(desc, count, sum, buckets, histogramSet.labels...)
			}
		}
	}
}

// tableValues returns values in the requested table to be used in metircs
func (e *Exporter) tableValues(module *bcc.Module, tableName string, labels []config.Label) ([]metricValue, []string, error) {
        sinkValues := []string{}
	exportValues := []metricValue{}

	table := bcc.NewTable(module.TableId(tableName), module)
	iter := table.Iter()
        t := time.Now()
	timeNow := t.UnixNano()
	for iter.Next() {
		key := iter.Key()
		raw, err := table.KeyBytesToStr(key)
		if err != nil {
			return nil, nil, fmt.Errorf("error decoding key %v", key)
		}

		mv := metricValue{
			raw:    raw,
			labels: make([]string, len(labels)),
		}

		mv.labels, err = e.decoders.DecodeLabels(key, labels)
		if err != nil {
			if err == decoder.ErrSkipLabelSet {
				continue
			}

			return nil, nil, err
		}

		value := bcc.GetHostByteOrder().Uint64(iter.Leaf())
		mv.value = float64(value)

		exportValues = append(exportValues, mv)

		sinkInfo := make(map[string]interface{})
		for idx, label := range labels {
			sinkInfo[label.Name] = mv.labels[idx]
		}
		if value == 0 {
			continue
		}
		sinkInfo[ahasSinkTimeKey] = timeNow
		sinkInfo[ahasSinkNameKey] = tableName
		sinkInfo[ahasSinkNodeKey] = e.nodeID
		sinkInfo[ahasSinkZoneKey] = e.nodeZone
		sinkInfo[ahasSinkRegionKey] = e.nodeRegion
		sinkInfo[ahasSinkProviderKey] = e.nodeProvider
		sinkInfo[ahasSinkClusterKey] = e.nodeCluster
		sinkInfo[ahasSinkValueKey] = mv.value
		jsonStr, err := json.Marshal(sinkInfo)
		if err == nil {
			sinkValues = append(sinkValues, fmt.Sprintf("%s\n", string(jsonStr)))
		}
				
	}
	return exportValues, sinkValues, nil
}

func (e Exporter) exportTables() (map[string]map[string][]metricValue, error) {
	tables := map[string]map[string][]metricValue{}

	for _, program := range e.config.Programs {
		module := e.modules[program.Name]
		if module == nil {
			return nil, fmt.Errorf("module for program %q is not attached", program.Name)
		}

		if _, ok := tables[program.Name]; !ok {
			tables[program.Name] = map[string][]metricValue{}
		}

		metricTables := map[string][]config.Label{}

		for _, counter := range program.Metrics.Counters {
			if counter.Table != "" {
				metricTables[counter.Table] = counter.Labels
			}
		}

		for _, histogram := range program.Metrics.Histograms {
			if histogram.Table != "" {
				metricTables[histogram.Table] = histogram.Labels
			}
		}

		for name, labels := range metricTables {
			metricValues, _, err := e.tableValues(e.modules[program.Name], name, labels)
			if err != nil {
				return nil, fmt.Errorf("error getting values for table %q of program %q: %s", name, program.Name, err)
			}

			tables[program.Name][name] = metricValues
		}
	}

	return tables, nil
}

// TablesHandler is a debug handler to print raw values of kernel maps
func (e *Exporter) TablesHandler(w http.ResponseWriter, r *http.Request) {
	tables, err := e.exportTables()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Add("Content-type", "text/plain")
		if _, err = fmt.Fprintf(w, "%s\n", err); err != nil {
			log.Printf("Error returning error to client %q: %s", r.RemoteAddr, err)
			return
		}
		return
	}

	w.Header().Add("Content-type", "text/plain")

	buf := []byte{}

	for program, tables := range tables {
		buf = append(buf, fmt.Sprintf("## Program: %s\n\n", program)...)

		for name, table := range tables {
			buf = append(buf, fmt.Sprintf("### Table: %s\n\n", name)...)

			buf = append(buf, ("```\n")...)
			for _, row := range table {
				buf = append(buf, fmt.Sprintf("%s (%v) -> %f\n", row.raw, row.labels, row.value)...)
			}
			buf = append(buf, ("```\n\n")...)
		}
	}

	if _, err = w.Write(buf); err != nil {
		log.Printf("Error returning table contents to client %q: %s", r.RemoteAddr, err)
	}
}

// metricValue is a row in a kernel map
type metricValue struct {
	// raw is a raw key value provided by kernel
	raw string
	// labels are decoded from the raw key
	labels []string
	// value is the kernel map value
	value float64
}

func (e *Exporter)addSinkEvent() {
	eventInfo := make(map[string]interface{})
	eventInfo[ahasEventNodeKey] = e.nodeID
	eventInfo[ahasEventZoneKey] = e.nodeZone
	eventInfo[ahasEventRegionKey] = e.nodeRegion
	eventInfo[ahasEventProviderKey] = e.nodeProvider
	eventInfo[ahasEventClusterKey] = e.nodeCluster
	eventInfo[ahasEventTimeKey] = time.Now().UnixNano()
	eventInfo[ahasEventNameKey] = ahasEventEbpfExporterStart
	eventInfo[ahasEventValueKey] = e.sinkOutPutFile

	fl, err := os.OpenFile(ahasEventPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0777)
	if err != nil  {
		log.Printf("open %s fail, %s", ahasEventPath, err)
		return
	}
	data, err := json.Marshal(eventInfo)
	if err != nil {
		log.Printf("write %s fail, %s", ahasEventPath, err)
		return
	}
        rawEvent := fmt.Sprintf("%s\n", data)
	_, err = fl.Write([]byte(rawEvent))
	if err != nil  {
		log.Printf("write %s fail, %s", ahasEventPath, err)
		return
	}
}

func (e *Exporter)dumpSinkValues(sinkValues []string) {
	if len(sinkValues) < 1 {
		return
	}
	timeNow := time.Now()
        sinkOutPutFile := fmt.Sprintf("%s/%s.gz", e.sinkRoot, timeNow.Local().Format("2006010215"))	
	if strings.Compare(sinkOutPutFile, e.sinkOutPutFile) != 0 {
		e.sinkOutPutFile = sinkOutPutFile
		e.addSinkEvent()
	}
	fl, err := os.OpenFile(e.sinkOutPutFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0777)
	if err != nil  {
		log.Printf("open %s fail, %s", e.sinkOutPutFile, err)
		return
	}
	defer fl.Close()
	gf := gzip.NewWriter(fl)
	fw := bufio.NewWriter(gf)
	for _, data := range sinkValues {
		fw.WriteString(data)
	}
	fw.Flush()
	gf.Close()
}
