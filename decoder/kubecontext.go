package decoder

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/iovisor/gobpf/bcc"

	"github.com/ahas-sigs/kube-ebpf-exporter/config"
	"github.com/docker/docker/client"
)

const (
	// when fail get kubernetes labe fail use DefaultKubeContextValue  as default
	DefaultKubeContextValue       = "unknown"
	MaxCachePidKubeInfoTimeSecond = 30
)

// KubeInfo kubernetes context info
type KubeInfo struct {
	kubePodNamespace  string
	kubePodName       string
	kubeContainerName string
	kubeSandboxID     string
	createTime        time.Time
}

// KubeContext kubernetes context info cache
type KubeContext struct {
	kubeContext    map[string]KubeInfo
	pidKubeContext map[uint32]KubeInfo
}

// KubePodNamespace is a decoder that transforms pid representation into kubernetes pod namespace
type KubePodNamespace struct {
	ctx KubeContext
}

// KubePodName is a decoder that transforms pid representation into kubernetes pod name
type KubePodName struct {
	ctx KubeContext
}

// KubeContainerName is a decoder that transforms pid representation into kubernetes pod container name
type KubeContainerName struct {
	ctx KubeContext
}

// Decode transforms pid representation into a kubernetes namespace and pod as string
func (k *KubePodNamespace) Decode(in []byte, conf config.Decoder) ([]byte, error) {
	byteOrder := bcc.GetHostByteOrder()
	info, err := k.ctx.getKubeInfo(byteOrder.Uint64(in))
	if err != nil {
		return nil, ErrSkipLabelSet
	}
	b := []byte(info.kubePodNamespace)
	return b, nil
}

// Decode transforms pid representation into a kubernetes pod name as string
func (k *KubePodName) Decode(in []byte, conf config.Decoder) ([]byte, error) {
	byteOrder := bcc.GetHostByteOrder()
	info, err := k.ctx.getKubeInfo(byteOrder.Uint64(in))
	if err != nil {
		return nil, ErrSkipLabelSet
	}
	b := []byte(info.kubePodName)
	return b, nil
}

// Decode transforms pid representation into a kubernetes container name as string
func (k *KubeContainerName) Decode(in []byte, conf config.Decoder) ([]byte, error) {
	byteOrder := bcc.GetHostByteOrder()
	info, err := k.ctx.getKubeInfo(byteOrder.Uint64(in))
	if err != nil {
		return nil, ErrSkipLabelSet
	}
	b := []byte(info.kubeContainerName)
	return b, nil
}

func (k *KubeContext) getKubeInfoFromCache(pidInfo uint64) (info KubeInfo, ok bool) {
	if k.pidKubeContext == nil || len(k.pidKubeContext) > 500 {
		k.pidKubeContext = make(map[uint32]KubeInfo)
		return
	}
	timeNow := time.Now()
	var pid uint32 = uint32(pidInfo)
	info, ok = k.pidKubeContext[pid]
	if ok {
		if timeNow.Sub(info.createTime) < time.Second*MaxCachePidKubeInfoTimeSecond {
			return
		}
		ok = false
		delete(k.pidKubeContext, pid)
		return
	}
	var ppid uint32 = uint32(pidInfo >> 32)
	info, ok = k.pidKubeContext[ppid]
	if ok {
		if timeNow.Sub(info.createTime) < time.Second*MaxCachePidKubeInfoTimeSecond {
			return
		}
		delete(k.pidKubeContext, ppid)
		ok = false
	}
	return
}

func (k *KubeContext) setKubeInfoFromCache(cgroupPid uint32, info KubeInfo) {
	info.createTime = time.Now()
	k.pidKubeContext[cgroupPid] = info
}

func (k *KubeContext) useKubeInfoFromComm(pidInfo uint64) (info KubeInfo) {
	var pid uint32 = uint32(pidInfo)
	var ppid uint32 = uint32(pidInfo >> 32)

	info.kubePodNamespace = DefaultKubeContextValue
	info.kubePodName = DefaultKubeContextValue
	info.kubeContainerName = DefaultKubeContextValue
	cgroupPid := pid
	path := fmt.Sprintf("/proc/%d/comm", cgroupPid)
	r, err := os.Open(path)
	if err != nil {
		cgroupPid = ppid
		path = fmt.Sprintf("/proc/%d/comm", cgroupPid)
		r, err = os.Open(path)
		if err != nil {
			return
		}
	}
	defer func() {
		if rerr := r.Close(); rerr != nil {
			err = rerr
		}
	}()
	reader := bufio.NewReader(r)
	text, _, err := reader.ReadLine()
	if err != nil {
		return
	}
	parts := strings.SplitN(string(text), "/", 2)
	command := parts[0]
	parts = strings.SplitN(command, ":", 2)
	command = parts[0]
	commLen := len(command)
	if commLen > 10 {
		commLen = 10
	}
	hostCommand := string(command[0:commLen])
	info.kubePodNamespace = "__host_command"
	info.kubePodName = hostCommand
	info.kubeContainerName = hostCommand
	k.setKubeInfoFromCache(cgroupPid, info)
	return
}

// getKubeInfo implement main logic convert container id to kubernetes context
func (k *KubeContext) getKubeInfo(pidInfo uint64) (info KubeInfo, err error) {
	var ok bool
	info, ok = k.getKubeInfoFromCache(pidInfo)
	if ok {
		return
	}
	var pid uint32 = uint32(pidInfo)
	var ppid uint32 = uint32(pidInfo >> 32)
	info.kubePodNamespace = DefaultKubeContextValue
	info.kubePodName = DefaultKubeContextValue
	info.kubeContainerName = DefaultKubeContextValue

	if pid <= 1 {
		info = k.useKubeInfoFromComm(pidInfo)
		return
	}
	cgroupPid := pid
	path := fmt.Sprintf("/proc/%d/cgroup", cgroupPid)
	r, err := os.Open(path)
	if err != nil {
		if ppid > 1 {
			cgroupPid = ppid
			path = fmt.Sprintf("/proc/%d/cgroup", cgroupPid)
			r, err = os.Open(path)
		}
		if err != nil {
			return
		}
	}
	defer func() {
		if rerr := r.Close(); rerr != nil {
			err = rerr
		}
	}()

	s := bufio.NewScanner(r)

	for s.Scan() {
		text := s.Text()
		//hierarchy-ID:subsystem-list:cgroup-path
		parts := strings.SplitN(text, ":", 3)
		if len(parts) < 3 {
			continue
		}
		cgroup := strings.Split(parts[2], "/")
		containerID := cgroup[len(cgroup)-1]
		if len(containerID) == 77 && strings.HasPrefix(containerID, "docker-") {
			containerID = containerID[7:71]
		}
		if len(containerID) == 64 {
			info, err = k.inspectKubeInfo(containerID)
			if err == nil {
				k.setKubeInfoFromCache(cgroupPid, info)
			} else {
				info = k.useKubeInfoFromComm(pidInfo)
			}
			return
		}
	}
	info = k.useKubeInfoFromComm(pidInfo)
	return
}

// inspectKubeInfo use docker client library to get kubernetes labels value
func (k *KubeContext) inspectKubeInfo(containerID string) (info KubeInfo, err error) {
	/// store more than 1000 container, need clean it for reduce memory use
	if k.kubeContext == nil || len(k.kubeContext) > 1000 {
		k.kubeContext = make(map[string]KubeInfo)
	}
	var ok bool
	info, ok = k.kubeContext[containerID]
	if ok {
		return
	}
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return
	}
	defer func() {
		if cerr := cli.Close(); cerr != nil {
			err = cerr
		}
	}()
	filters := filters.NewArgs()
	if len(k.kubeContext) > 0 {
		filters.Add("id", containerID)
	}
	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{
		Filters: filters,
	})
	if err != nil {
		return
	}
	for _, container := range containers {
		if container.Labels != nil {
			var tmp KubeInfo
			tmp.kubePodNamespace = container.Labels["io.kubernetes.pod.namespace"]
			var fullInfo bool = true
			if tmp.kubePodNamespace == "" {
				fullInfo = false
				tmp.kubePodNamespace = DefaultKubeContextValue
			}
			tmp.kubePodName = container.Labels["io.kubernetes.pod.name"]
			if tmp.kubePodName == "" {
				fullInfo = false
				tmp.kubePodName = DefaultKubeContextValue
			}
			tmp.kubeContainerName = container.Labels["io.kubernetes.container.name"]
			if tmp.kubeContainerName == "" {
				fullInfo = false
				tmp.kubeContainerName = DefaultKubeContextValue
			}
			tmp.kubeSandboxID = container.Labels["io.kubernetes.sandbox.id"]
			if fullInfo {
				k.kubeContext[container.ID] = tmp
				if len(tmp.kubeSandboxID) == 64 {
					k.kubeContext[tmp.kubeSandboxID] = tmp
				}
			}
		}
	}
	info, ok = k.kubeContext[containerID]
	if !ok {
		err = fmt.Errorf("match none")
	}
	return
}
