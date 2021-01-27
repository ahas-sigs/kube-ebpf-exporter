package decoder

import (
	"bytes"
	"testing"

	"github.com/ahas-sigs/kube-ebpf-exporter/v2/config"
)

func TestKubePodNamespaceDecoder(t *testing.T) {
	cases := []struct {
		in  []byte
		out []byte
	}{
		{
			in:  []byte{0x0, 0x0, 0x0, 0x0},
			out: nil,
		},
	}

	for _, c := range cases {
		d := &KubePodNamespace{}

		out, err := d.Decode(c.in, config.Decoder{})
		if err != nil && err != ErrSkipLabelSet{
			t.Errorf("Error decoding %#v to %#v: %s", c.in, c.out, err)
		}

		if !bytes.Equal(out, c.out) {
			t.Errorf("Expected %#v, got %#v", c.out, out)
		}
	}
}
