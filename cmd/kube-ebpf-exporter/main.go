package main

import (
	"log"
	"net/http"

	"github.com/ahas-sigs/kube-ebpf-exporter/v2/config"
	"github.com/ahas-sigs/kube-ebpf-exporter/v2/exporter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
	yaml "gopkg.in/yaml.v2"
)

func main() {
	listenAddress := kingpin.Flag("web.listen-address", "The address to listen on for HTTP requests").Default(":9435").String()
	nodeID := kingpin.Flag("node-id", "node id").Default("localhost").String()
	configFile := kingpin.Flag("config.file", "Config file path").Default("config.yaml").File()
	debug := kingpin.Flag("debug", "Enable debug").Bool()
	kingpin.Version(version.Print("ebpf_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	config := config.Config{}

	err := yaml.NewDecoder(*configFile).Decode(&config)
	if err != nil {
		log.Fatalf("Error reading config file: %s", err)
	}

	e := exporter.New(*nodeID, config)
	err = e.Attach()
	if err != nil {
		log.Fatalf("Error attaching exporter: %s", err)
	}

	log.Printf("Starting with %d programs found in the config", len(config.Programs))

	err = prometheus.Register(e)
	if err != nil {
		log.Fatalf("Error registering exporter: %s", err)
	}

	http.Handle("/metrics", promhttp.Handler())

	if *debug {
		log.Printf("Debug enabled, exporting raw tables on /tables")
		http.HandleFunc("/tables", e.TablesHandler)
	}

	log.Printf("Listening on %s", *listenAddress)
	err = http.ListenAndServe(*listenAddress, nil)
	if err != nil {
		log.Fatalf("Error listening on %s: %s", *listenAddress, err)
	}
}
