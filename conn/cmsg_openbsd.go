package conn

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"unsafe"

	"golang.org/x/sys/unix"
)

const socketControlMessageBufferSize = unix.SizeofCmsghdr + max(alignedSizeofInet4Addr, alignedSizeofInet6Pktinfo) +
	unix.SizeofCmsghdr + alignedSizeofDstPort

const (
	sizeofInet4Addr = 4 // sizeof(struct in_addr)
	sizeofDstPort   = 2 // sizeof(u_int16_t)
)

func cmsgAlign(n int) int {
	salign := unix.SizeofPtr
	// OpenBSD armv7 requires 64-bit alignment.
	if runtime.GOARCH == "arm" {
		salign = 8
	}
	return (n + salign - 1) & ^(salign - 1)
}

func parseSocketControlMessage(cmsg []byte) (m SocketControlMessage, err error) {
	for len(cmsg) >= unix.SizeofCmsghdr {
		cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(unsafe.SliceData(cmsg)))
		msgSize := cmsgAlign(int(cmsghdr.Len))
		if cmsghdr.Len < unix.SizeofCmsghdr || msgSize > len(cmsg) {
			return m, fmt.Errorf("invalid control message length %d", cmsghdr.Len)
		}

		switch cmsghdr.Level {
		case unix.IPPROTO_IP:
			switch cmsghdr.Type {
			case unix.IP_RECVDSTADDR:
				if len(cmsg) < unix.SizeofCmsghdr+sizeofInet4Addr {
					return m, fmt.Errorf("invalid IP_RECVDSTADDR control message length %d", cmsghdr.Len)
				}
				addr := [sizeofInet4Addr]byte(cmsg[unix.SizeofCmsghdr:])
				m.PktinfoAddr = netip.AddrFrom4(addr)
				// OpenBSD also uses this for transparent proxies.
				m.OriginalDestinationAddrPort = netip.AddrPortFrom(m.PktinfoAddr, m.OriginalDestinationAddrPort.Port())

			case unix.IP_RECVDSTPORT:
				if len(cmsg) < unix.SizeofCmsghdr+sizeofDstPort {
					return m, fmt.Errorf("invalid IP_RECVDSTPORT control message length %d", cmsghdr.Len)
				}
				port := binary.BigEndian.Uint16(cmsg[unix.SizeofCmsghdr:])
				m.OriginalDestinationAddrPort = netip.AddrPortFrom(m.PktinfoAddr, port)
			}

		case unix.IPPROTO_IPV6:
			switch cmsghdr.Type {
			case unix.IPV6_PKTINFO:
				if len(cmsg) < unix.SizeofCmsghdr+unix.SizeofInet6Pktinfo {
					return m, fmt.Errorf("invalid IPV6_PKTINFO control message length %d", cmsghdr.Len)
				}
				var pktinfo unix.Inet6Pktinfo
				_ = copy(unsafe.Slice((*byte)(unsafe.Pointer(&pktinfo)), unix.SizeofInet6Pktinfo), cmsg[unix.SizeofCmsghdr:])
				m.PktinfoAddr = netip.AddrFrom16(pktinfo.Addr)
				m.PktinfoIfindex = pktinfo.Ifindex
				// OpenBSD also uses this for transparent proxies.
				m.OriginalDestinationAddrPort = netip.AddrPortFrom(m.PktinfoAddr, m.OriginalDestinationAddrPort.Port())

			case unix.IPV6_RECVDSTPORT:
				if len(cmsg) < unix.SizeofCmsghdr+sizeofDstPort {
					return m, fmt.Errorf("invalid IPV6_RECVDSTPORT control message length %d", cmsghdr.Len)
				}
				port := binary.BigEndian.Uint16(cmsg[unix.SizeofCmsghdr:])
				m.OriginalDestinationAddrPort = netip.AddrPortFrom(m.PktinfoAddr, port)
			}
		}

		cmsg = cmsg[msgSize:]
	}

	return m, nil
}

const (
	alignedSizeofInet4Addr    = (sizeofInet4Addr + unix.SizeofPtr - 1) & ^(unix.SizeofPtr - 1)
	alignedSizeofInet6Pktinfo = (unix.SizeofInet6Pktinfo + unix.SizeofPtr - 1) & ^(unix.SizeofPtr - 1)
	alignedSizeofDstPort      = (sizeofDstPort + unix.SizeofPtr - 1) & ^(unix.SizeofPtr - 1)
)

func (m SocketControlMessage) appendTo(b []byte) []byte {
	switch {
	case m.PktinfoAddr.Is4():
		bLen := len(b)
		b = slices.Grow(b, unix.SizeofCmsghdr+alignedSizeofInet4Addr)[:bLen+unix.SizeofCmsghdr+alignedSizeofInet4Addr]
		msgBuf := b[bLen:]
		cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(unsafe.SliceData(msgBuf)))
		*cmsghdr = unix.Cmsghdr{
			Len:   unix.SizeofCmsghdr + sizeofInet4Addr,
			Level: unix.IPPROTO_IP,
			Type:  unix.IP_SENDSRCADDR,
		}
		addr := m.PktinfoAddr.As4()
		_ = copy(msgBuf[unix.SizeofCmsghdr:], addr[:])

	case m.PktinfoAddr.Is6():
		bLen := len(b)
		b = slices.Grow(b, unix.SizeofCmsghdr+alignedSizeofInet6Pktinfo)[:bLen+unix.SizeofCmsghdr+alignedSizeofInet6Pktinfo]
		msgBuf := b[bLen:]
		cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(unsafe.SliceData(msgBuf)))
		*cmsghdr = unix.Cmsghdr{
			Len:   unix.SizeofCmsghdr + unix.SizeofInet6Pktinfo,
			Level: unix.IPPROTO_IPV6,
			Type:  unix.IPV6_PKTINFO,
		}
		pktinfo := unix.Inet6Pktinfo{
			Addr:    m.PktinfoAddr.As16(),
			Ifindex: m.PktinfoIfindex,
		}
		_ = copy(msgBuf[unix.SizeofCmsghdr:], unsafe.Slice((*byte)(unsafe.Pointer(&pktinfo)), unix.SizeofInet6Pktinfo))
	}

	return b
}
