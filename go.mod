module github.com/ahas-sigs/kube-ebpf-exporter

require (
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78 // indirect
	github.com/Microsoft/go-winio v0.4.14 // indirect
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v1.13.1
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/gogo/protobuf v1.3.1 // indirect
	github.com/gorilla/mux v1.7.4 // indirect
	github.com/iovisor/gobpf v0.0.0-20191017091429-c3024dcc6881
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/prometheus/client_golang v1.9.0
	github.com/prometheus/common v0.15.0
	golang.org/x/sys v0.0.0-20201214210602-f9fddec55a1e
	google.golang.org/grpc v1.28.0 // indirect
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/yaml.v2 v2.3.0
	gotest.tools v2.2.0+incompatible // indirect
)

replace github.com/docker/docker v1.13.1 => github.com/docker/engine v0.0.0-20190822180741-9552f2b2fdde

go 1.13
