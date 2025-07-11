package conn

import (
	"fmt"
	"net/netip"
	"slices"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	socketControlMessageBufferSize = alignedSizeofCmsghdr + max(alignedSizeofInet4Addr, alignedSizeofInet6Pktinfo) +
		alignedSizeofCmsghdr + max(alignedSizeofSockaddrInet4, alignedSizeofSockaddrInet6)

	alignedSizeofInet4Addr     = (sizeofInet4Addr + cmsgAlignTo - 1) & ^(cmsgAlignTo - 1)
	alignedSizeofInet6Pktinfo  = (unix.SizeofInet6Pktinfo + cmsgAlignTo - 1) & ^(cmsgAlignTo - 1)
	alignedSizeofSockaddrInet4 = (unix.SizeofSockaddrInet4 + cmsgAlignTo - 1) & ^(cmsgAlignTo - 1)
	alignedSizeofSockaddrInet6 = (unix.SizeofSockaddrInet6 + cmsgAlignTo - 1) & ^(cmsgAlignTo - 1)

	sizeofInet4Addr = 4 // sizeof(struct in_addr)
)

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
				if len(cmsg) < alignedSizeofCmsghdr+sizeofInet4Addr {
					return m, fmt.Errorf("invalid IP_RECVDSTADDR control message length %d", cmsghdr.Len)
				}
				addr := [sizeofInet4Addr]byte(cmsg[alignedSizeofCmsghdr:])
				m.PktinfoAddr = netip.AddrFrom4(addr)

			case unix.IP_ORIGDSTADDR:
				if len(cmsg) < alignedSizeofCmsghdr+unix.SizeofSockaddrInet4 {
					return m, fmt.Errorf("invalid IP_ORIGDSTADDR control message length %d", cmsghdr.Len)
				}
				var rsa4 unix.RawSockaddrInet4
				_ = copy(unsafe.Slice((*byte)(unsafe.Pointer(&rsa4)), unix.SizeofSockaddrInet4), cmsg[alignedSizeofCmsghdr:])
				m.OriginalDestinationAddrPort = netip.AddrPortFrom(netip.AddrFrom4(rsa4.Addr), rsa4.Port)
			}

		case unix.IPPROTO_IPV6:
			switch cmsghdr.Type {
			case unix.IPV6_PKTINFO:
				if len(cmsg) < alignedSizeofCmsghdr+unix.SizeofInet6Pktinfo {
					return m, fmt.Errorf("invalid IPV6_PKTINFO control message length %d", cmsghdr.Len)
				}
				var pktinfo unix.Inet6Pktinfo
				_ = copy(unsafe.Slice((*byte)(unsafe.Pointer(&pktinfo)), unix.SizeofInet6Pktinfo), cmsg[alignedSizeofCmsghdr:])
				m.PktinfoAddr = netip.AddrFrom16(pktinfo.Addr)
				m.PktinfoIfindex = pktinfo.Ifindex

			case unix.IPV6_ORIGDSTADDR:
				if len(cmsg) < alignedSizeofCmsghdr+unix.SizeofSockaddrInet6 {
					return m, fmt.Errorf("invalid IPV6_ORIGDSTADDR control message length %d", cmsghdr.Len)
				}
				var rsa6 unix.RawSockaddrInet6
				_ = copy(unsafe.Slice((*byte)(unsafe.Pointer(&rsa6)), unix.SizeofSockaddrInet6), cmsg[alignedSizeofCmsghdr:])
				m.OriginalDestinationAddrPort = netip.AddrPortFrom(netip.AddrFrom16(rsa6.Addr), rsa6.Port)
			}
		}

		cmsg = cmsg[msgSize:]
	}

	return m, nil
}

func (m SocketControlMessage) appendTo(b []byte) []byte {
	switch {
	case m.PktinfoAddr.Is4():
		bLen := len(b)
		b = slices.Grow(b, alignedSizeofCmsghdr+alignedSizeofInet4Addr)[:bLen+alignedSizeofCmsghdr+alignedSizeofInet4Addr]
		msgBuf := b[bLen:]
		cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(unsafe.SliceData(msgBuf)))
		*cmsghdr = unix.Cmsghdr{
			Len:   alignedSizeofCmsghdr + sizeofInet4Addr,
			Level: unix.IPPROTO_IP,
			Type:  unix.IP_SENDSRCADDR,
		}
		addr := m.PktinfoAddr.As4()
		_ = copy(msgBuf[alignedSizeofCmsghdr:], addr[:])

	case m.PktinfoAddr.Is6():
		bLen := len(b)
		b = slices.Grow(b, alignedSizeofCmsghdr+alignedSizeofInet6Pktinfo)[:bLen+alignedSizeofCmsghdr+alignedSizeofInet6Pktinfo]
		msgBuf := b[bLen:]
		cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(unsafe.SliceData(msgBuf)))
		*cmsghdr = unix.Cmsghdr{
			Len:   alignedSizeofCmsghdr + unix.SizeofInet6Pktinfo,
			Level: unix.IPPROTO_IPV6,
			Type:  unix.IPV6_PKTINFO,
		}
		pktinfo := unix.Inet6Pktinfo{
			Addr:    m.PktinfoAddr.As16(),
			Ifindex: m.PktinfoIfindex,
		}
		_ = copy(msgBuf[alignedSizeofCmsghdr:], unsafe.Slice((*byte)(unsafe.Pointer(&pktinfo)), unix.SizeofInet6Pktinfo))
	}

	return b
}
