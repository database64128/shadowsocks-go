package conn

import (
	"fmt"
	"net/netip"
	"slices"
	"unsafe"

	"golang.org/x/sys/unix"
)

const socketControlMessageBufferSize = unix.SizeofCmsghdr + max(alignedSizeofInet4Pktinfo, alignedSizeofInet6Pktinfo) +
	unix.SizeofCmsghdr + max(alignedSizeofSockaddrInet4, alignedSizeofSockaddrInet6) +
	unix.SizeofCmsghdr + max(alignedSizeofGSOSegmentSize, alignedSizeofGROSegmentSize)

const (
	sizeofGSOSegmentSize = 2 // int(unsafe.Sizeof(uint16(0)))
	sizeofGROSegmentSize = 4 // int(unsafe.Sizeof(int32(0)))
)

func cmsgAlign(n int) int {
	return (n + unix.SizeofPtr - 1) & ^(unix.SizeofPtr - 1)
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
			case unix.IP_PKTINFO:
				if len(cmsg) < unix.SizeofCmsghdr+unix.SizeofInet4Pktinfo {
					return m, fmt.Errorf("invalid IP_PKTINFO control message length %d", cmsghdr.Len)
				}
				var pktinfo unix.Inet4Pktinfo
				_ = copy(unsafe.Slice((*byte)(unsafe.Pointer(&pktinfo)), unix.SizeofInet4Pktinfo), cmsg[unix.SizeofCmsghdr:])
				m.PktinfoAddr = netip.AddrFrom4(pktinfo.Spec_dst)
				m.PktinfoIfindex = uint32(pktinfo.Ifindex)

			case unix.IP_ORIGDSTADDR:
				if len(cmsg) < unix.SizeofCmsghdr+unix.SizeofSockaddrInet4 {
					return m, fmt.Errorf("invalid IP_ORIGDSTADDR control message length %d", cmsghdr.Len)
				}
				var rsa4 unix.RawSockaddrInet4
				_ = copy(unsafe.Slice((*byte)(unsafe.Pointer(&rsa4)), unix.SizeofSockaddrInet4), cmsg[unix.SizeofCmsghdr:])
				m.OriginalDestinationAddrPort = netip.AddrPortFrom(netip.AddrFrom4(rsa4.Addr), rsa4.Port)
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

			case unix.IPV6_ORIGDSTADDR:
				if len(cmsg) < unix.SizeofCmsghdr+unix.SizeofSockaddrInet6 {
					return m, fmt.Errorf("invalid IPV6_ORIGDSTADDR control message length %d", cmsghdr.Len)
				}
				var rsa6 unix.RawSockaddrInet6
				_ = copy(unsafe.Slice((*byte)(unsafe.Pointer(&rsa6)), unix.SizeofSockaddrInet6), cmsg[unix.SizeofCmsghdr:])
				m.OriginalDestinationAddrPort = netip.AddrPortFrom(netip.AddrFrom16(rsa6.Addr), rsa6.Port)
			}

		case unix.IPPROTO_UDP:
			switch cmsghdr.Type {
			case unix.UDP_GRO:
				if len(cmsg) < unix.SizeofCmsghdr+sizeofGROSegmentSize {
					return m, fmt.Errorf("invalid UDP_GRO control message length %d", cmsghdr.Len)
				}
				_ = copy(unsafe.Slice((*byte)(unsafe.Pointer(&m.SegmentSize)), sizeofGROSegmentSize), cmsg[unix.SizeofCmsghdr:])
			}
		}

		cmsg = cmsg[msgSize:]
	}

	return m, nil
}

const (
	alignedSizeofInet4Pktinfo   = (unix.SizeofInet4Pktinfo + unix.SizeofPtr - 1) & ^(unix.SizeofPtr - 1)
	alignedSizeofInet6Pktinfo   = (unix.SizeofInet6Pktinfo + unix.SizeofPtr - 1) & ^(unix.SizeofPtr - 1)
	alignedSizeofSockaddrInet4  = (unix.SizeofSockaddrInet4 + unix.SizeofPtr - 1) & ^(unix.SizeofPtr - 1)
	alignedSizeofSockaddrInet6  = (unix.SizeofSockaddrInet6 + unix.SizeofPtr - 1) & ^(unix.SizeofPtr - 1)
	alignedSizeofGSOSegmentSize = (sizeofGSOSegmentSize + unix.SizeofPtr - 1) & ^(unix.SizeofPtr - 1)
	alignedSizeofGROSegmentSize = (sizeofGROSegmentSize + unix.SizeofPtr - 1) & ^(unix.SizeofPtr - 1)
)

func (m SocketControlMessage) appendTo(b []byte) []byte {
	switch {
	case m.PktinfoAddr.Is4():
		bLen := len(b)
		b = slices.Grow(b, unix.SizeofCmsghdr+alignedSizeofInet4Pktinfo)[:bLen+unix.SizeofCmsghdr+alignedSizeofInet4Pktinfo]
		msgBuf := b[bLen:]
		cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(unsafe.SliceData(msgBuf)))
		*cmsghdr = unix.Cmsghdr{
			Len:   unix.SizeofCmsghdr + unix.SizeofInet4Pktinfo,
			Level: unix.IPPROTO_IP,
			Type:  unix.IP_PKTINFO,
		}
		pktinfo := unix.Inet4Pktinfo{
			Ifindex:  int32(m.PktinfoIfindex),
			Spec_dst: m.PktinfoAddr.As4(),
		}
		_ = copy(msgBuf[unix.SizeofCmsghdr:], unsafe.Slice((*byte)(unsafe.Pointer(&pktinfo)), unix.SizeofInet4Pktinfo))

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

	if m.SegmentSize > 0 {
		bLen := len(b)
		b = slices.Grow(b, unix.SizeofCmsghdr+alignedSizeofGSOSegmentSize)[:bLen+unix.SizeofCmsghdr+alignedSizeofGSOSegmentSize]
		msgBuf := b[bLen:]
		cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(unsafe.SliceData(msgBuf)))
		*cmsghdr = unix.Cmsghdr{
			Len:   unix.SizeofCmsghdr + sizeofGSOSegmentSize,
			Level: unix.IPPROTO_UDP,
			Type:  unix.UDP_SEGMENT,
		}
		segmentSize := uint16(m.SegmentSize)
		_ = copy(msgBuf[unix.SizeofCmsghdr:], unsafe.Slice((*byte)(unsafe.Pointer(&segmentSize)), sizeofGSOSegmentSize))
	}

	return b
}
