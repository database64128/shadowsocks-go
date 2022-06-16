package direct

import (
	"testing"

	"github.com/database64128/shadowsocks-go/test"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

func TestDirectStreamReadWriter(t *testing.T) {
	pl, pr := test.NewDuplexPipe()

	l := DirectStreamReadWriter{
		rw: pl,
	}
	r := DirectStreamReadWriter{
		rw: pr,
	}

	zerocopy.ReadWriterTestFunc(t, &l, &r)
}
