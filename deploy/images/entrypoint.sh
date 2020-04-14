#!/bin/bash

function init_ahas_config()
{
  default_kernel="/ahas-sigs/kube-ebpf-exporter/ahas-kernel-3.10.yaml"
  spec_kernel=`uname -r | awk -F '.'  '{print "/ahas-sigs/kube-ebpf-exporter/ahas-kernel-"$1"."$2".yaml"}'`
  config_file="/ahas-sigs/kube-ebpf-exporter/ahas.yaml"
  if test -f ${config_file}
  then
    echo " ${config_file} exist use default"
  else
    if test -f ${spec_kernel}
    then
      cp ${spec_kernel} ${config_file} 
      echo " use spec kernel config ${spec_kernel}"
    else
      cp ${default_kernel} ${config_file} 
      echo " use default kernel config ${default_kernel}"
    fi
  fi
}

init_ahas_config

echo "AHAS_LISTEN_PORT: ${AHAS_LISTEN_PORT}"
if [ -z "${AHAS_LISTEN_PORT}" ]
then
  AHAS_LISTEN_ADDRESS=":9435"
else
  AHAS_LISTEN_ADDRESS=":${AHAS_LISTEN_PORT}"
fi
/ahas-sigs/kube-ebpf-exporter/kube-ebpf-exporter --web.listen-address="$AHAS_LISTEN_ADDRESS" --node-id=$NODE_ID --config.file=/ahas-sigs/kube-ebpf-exporter/ahas.yaml

