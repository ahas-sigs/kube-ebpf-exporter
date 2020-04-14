#!/bin/bash
CUR_DIR=$(cd "$(dirname "$0")";pwd)
version=v1.0.0
docker build --no-cache -t kube-ebpf-exporter:$version .

docker tag kube-ebpf-exporter:$version huaizong/ahas-sigs-kube-ebpf-exporter:$version

docker push huaizong/ahas-sigs-kube-ebpf-exporter:$version
