# kube-ebpf-exporter

[![Build Status](https://travis-ci.org/ahas-sigs/kube-ebpf-exporter.svg?branch=master)](https://travis-ci.org/ahas-sigs/kube-ebpf-exporter)

Prometheus exporter for custom eBPF metrics.

This is a fork of [cloudflare/ebpf-exporter](https://github.com/cloudflare/ebpf_exporter), improve for kubernetes node environment.

Motivation of this exporter is to allow you to write eBPF code and export
metrics that are not otherwise accessible from the Linux kernel.

eBPF was [described by](https://lkml.org/lkml/2015/4/14/232) Ingo Molnár as:

> One of the more interesting features in this cycle is the ability to attach
> eBPF programs (user-defined, sandboxed bytecode executed by the kernel)
> to kprobes. This allows user-defined instrumentation on a live kernel image
> that can never crash, hang or interfere with the kernel negatively.

An easy way of thinking about this exporter is bcc tools as prometheus metrics:

* https://iovisor.github.io/bcc

## Reading material

* https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md
* http://www.brendangregg.com/ebpf.html

## Building and running

To build, you need to have `libbcc` installed:

* https://github.com/iovisor/bcc/blob/master/INSTALL.md

You can use pre-compiled binary from Releases:

* https://github.com/cloudflare/ebpf_exporter/releases

That still requires you to have `libbcc`. To build release binaries yourself:

```
$ make release-binaries
```

To build a package from latest sources:

```
$ go get -u -v github.com/ahas-sigs/kube-ebpf-exporter/...
```

To run with [`kernel-3.10`](examples/ahas-kernel-3.10.yaml) config (you need `root` privileges, unser kernel 3.10 version, such as centos 7.6):

```
$ ~/go/bin/kube-ebpf_exporter --config.file=src/github.com/ahas-sigs/kube-ebpf-exporter/examples/ahas-kernel-3.10.yaml
```


## Benchmarking overhead

See [benchmark](benchmark) directory to get an idea of how low ebpf overhead is.

## Supported scenarios

Currently the only supported way of getting data out of the kernel
is via maps (we call them tables in configuration). See:

* https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#maps

See [examples](#examples) section for real world examples.

If you have examples you want to share, please feel free to open a PR.

## Configuration

Skip to [format](#configuration-file-format) to see the full specification.

### Examples

You can find additional examples in [examples](examples) directory.

Unless otherwise specified, all examples are expected to work on centos kernel 3.10.0-1062,
which is the current kernerl version of Centos 7.
