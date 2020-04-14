FROM centos:7.6.1810
MAINTAINER huaizongfujian@gmail.com
RUN yum install -y epel-release bcc-devel kernel kernel-devel
RUN yum install -y golang

COPY ./ /go/ebpf-exporter

RUN cd /go/ebpf-exporter && GOPATH="" GOPROXY="off" GOFLAGS="-mod=vendor" go install -v ./...
