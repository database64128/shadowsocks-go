package stats

import "testing"

func collect(t *testing.T, c Collector) {
	t.Helper()
	c.CollectTCPSession("Steve", 1024, 2048)
	c.CollectUDPSessionUplink("Alex", 1, 3072)
	c.CollectUDPSessionDownlink("Steve", 2, 4096)
	c.CollectTCPSession("Alex", 5120, 6144)
	c.CollectUDPSessionDownlink("Alex", 4, 7168)
	c.CollectUDPSessionUplink("Steve", 8, 8192)
	c.CollectTCPSession("Steve", 9216, 10240)
	c.CollectUDPSessionDownlink("Alex", 16, 11264)
	c.CollectUDPSessionDownlink("Steve", 32, 12288)
	c.CollectUDPSessionDownlink("Alex", 64, 13312)
	c.CollectUDPSessionUplink("Steve", 128, 14336)
	c.CollectUDPSessionUplink("Alex", 256, 15360)
	c.CollectUDPSessionUplink("Alex", 512, 16384)
	c.CollectTCPSession("Steve", 17408, 18432)
	c.CollectUDPSessionDownlink("Alex", 1024, 19456)
	c.CollectUDPSessionUplink("Alex", 2048, 20480)
}

func verify(t *testing.T, c Collector) {
	t.Helper()
	s := c.Snapshot()
	if s.Traffic.DownlinkPackets != 1142 {
		t.Errorf("expected 1142 downlink packets, got %d", s.Traffic.DownlinkPackets)
	}
	if s.Traffic.DownlinkBytes != 100352 {
		t.Errorf("expected 100352 downlink bytes, got %d", s.Traffic.DownlinkBytes)
	}
	if s.Traffic.UplinkPackets != 2953 {
		t.Errorf("expected 2953 uplink packets, got %d", s.Traffic.UplinkPackets)
	}
	if s.Traffic.UplinkBytes != 114688 {
		t.Errorf("expected 114688 uplink bytes, got %d", s.Traffic.UplinkBytes)
	}
	if s.Traffic.TCPSessions != 4 {
		t.Errorf("expected 4 TCP sessions, got %d", s.Traffic.TCPSessions)
	}
	if s.Traffic.UDPSessions != 6 {
		t.Errorf("expected 6 UDP sessions, got %d", s.Traffic.UDPSessions)
	}
	if len(s.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(s.Users))
	}
	for _, u := range s.Users {
		switch u.Name {
		case "Alex":
			if u.Traffic.DownlinkPackets != 1108 {
				t.Errorf("expected 1108 downlink packets for Alex, got %d", u.Traffic.DownlinkPackets)
			}
			if u.Traffic.DownlinkBytes != 56320 {
				t.Errorf("expected 56320 downlink bytes for Alex, got %d", u.Traffic.DownlinkBytes)
			}
			if u.Traffic.UplinkPackets != 2817 {
				t.Errorf("expected 2817 uplink packets for Alex, got %d", u.Traffic.UplinkPackets)
			}
			if u.Traffic.UplinkBytes != 61440 {
				t.Errorf("expected 61440 uplink bytes for Alex, got %d", u.Traffic.UplinkBytes)
			}
			if u.Traffic.TCPSessions != 1 {
				t.Errorf("expected 1 TCP session for Alex, got %d", u.Traffic.TCPSessions)
			}
			if u.Traffic.UDPSessions != 4 {
				t.Errorf("expected 4 UDP sessions for Alex, got %d", u.Traffic.UDPSessions)
			}
		case "Steve":
			if u.Traffic.DownlinkPackets != 34 {
				t.Errorf("expected 34 downlink packets for Steve, got %d", u.Traffic.DownlinkPackets)
			}
			if u.Traffic.DownlinkBytes != 44032 {
				t.Errorf("expected 44032 downlink bytes for Steve, got %d", u.Traffic.DownlinkBytes)
			}
			if u.Traffic.UplinkPackets != 136 {
				t.Errorf("expected 136 uplink packets for Steve, got %d", u.Traffic.UplinkPackets)
			}
			if u.Traffic.UplinkBytes != 53248 {
				t.Errorf("expected 53248 uplink bytes for Steve, got %d", u.Traffic.UplinkBytes)
			}
			if u.Traffic.TCPSessions != 3 {
				t.Errorf("expected 3 TCP sessions for Steve, got %d", u.Traffic.TCPSessions)
			}
			if u.Traffic.UDPSessions != 2 {
				t.Errorf("expected 2 UDP sessions for Steve, got %d", u.Traffic.UDPSessions)
			}
		default:
			t.Errorf("unexpected user %s", u.Name)
		}
	}
}

func TestServerCollector(t *testing.T) {
	c := NewServerCollector()
	collect(t, c)
	verify(t, c)
}

func TestNoopCollector(t *testing.T) {
	c := NoopCollector{}
	collect(t, &c)
	s := c.Snapshot()
	var zero Traffic
	if s.Traffic != zero {
		t.Errorf("expected zero traffic, got %+v", s.Traffic)
	}
	if len(s.Users) != 0 {
		t.Errorf("expected zero users, got %d", len(s.Users))
	}
}
