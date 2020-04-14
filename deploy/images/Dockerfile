FROM centos:7.6.1810
MAINTAINER huaizongfujian@gmail.com

RUN yum install -y epel-release bcc-devel kernel kernel-devel

RUN mkdir -p /ahas-sigs/kube-ebpf-exporter/ebpf
COPY ahas-kernel-3.10.yaml /ahas-sigs/kube-ebpf-exporter
COPY kube-ebpf-exporter /ahas-sigs/kube-ebpf-exporter/kube-ebpf-exporter
RUN chmod +x /ahas-sigs/kube-ebpf-exporter/kube-ebpf-exporter

EXPOSE 9435/tcp
WORKDIR /ahas-sigs/kube-ebpf-exporter
ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
