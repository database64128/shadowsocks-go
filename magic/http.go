package magic

import (
	"bufio"
	"net/http"
	_ "unsafe"
)

//go:linkname ReadRequest net/http.readRequest
//go:noescape
func ReadRequest(b *bufio.Reader) (req *http.Request, err error)
