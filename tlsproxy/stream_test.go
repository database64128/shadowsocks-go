package tlsproxy_test

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/netiotest"
	"github.com/database64128/shadowsocks-go/tlsproxy"
	"github.com/database64128/shadowsocks-go/tslog"
	"github.com/database64128/shadowsocks-go/tslogtest"
)

const (
	rootCommonName   = "Root"
	clientCommonName = "Client"
	serverCommonName = "Server"
)

var (
	rootCAs     *x509.CertPool
	clientCerts []tls.Certificate
	serverCerts []tls.Certificate
)

func testTime() time.Time {
	return time.Unix(1476984729, 0)
}

func init() {
	notBefore := testTime().Add(-100 * 24 * time.Hour)
	notAfter := testTime().Add(100 * 24 * time.Hour)
	serial := int64(0)
	nextSerial := func() *big.Int {
		serial++
		return big.NewInt(serial)
	}

	// Root CA key and cert.
	rootKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		panic(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: rootCommonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.PublicKey(), rootKey)
	if err != nil {
		panic(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		panic(err)
	}

	rootCAs = x509.NewCertPool()
	rootCAs.AddCert(rootCert)

	// Client key and cert.
	clientKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		panic(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: clientCommonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, rootCert, clientKey.PublicKey(), rootKey)
	if err != nil {
		panic(err)
	}
	clientLeaf, err := x509.ParseCertificate(clientDER)
	if err != nil {
		panic(err)
	}
	clientCerts = []tls.Certificate{
		{
			Certificate: [][]byte{clientDER},
			PrivateKey:  clientKey,
			Leaf:        clientLeaf,
		},
	}

	// Server key and cert.
	serverKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		panic(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: serverCommonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{serverCommonName},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, rootCert, serverKey.PublicKey(), rootKey)
	if err != nil {
		panic(err)
	}
	serverLeaf, err := x509.ParseCertificate(serverDER)
	if err != nil {
		panic(err)
	}
	serverCerts = []tls.Certificate{
		{
			Certificate: [][]byte{serverDER},
			PrivateKey:  serverKey,
			Leaf:        serverLeaf,
		},
	}
}

type testInnerServer struct {
	username string
}

func (testInnerServer) StreamServerInfo() netio.StreamServerInfo {
	return netio.StreamServerInfo{}
}

func (s testInnerServer) HandleStream(c netio.Conn, _ *tslog.Logger) (netio.ConnRequest, error) {
	tc, ok := c.(*tls.Conn)
	if !ok {
		return netio.ConnRequest{}, fmt.Errorf("c is %T, want *tls.Conn", c)
	}
	nc := tc.NetConn()
	pc, ok := nc.(*netiotest.PipeConn)
	if !ok {
		return netio.ConnRequest{}, fmt.Errorf("nc is %T, want *PipeConn", nc)
	}
	return netio.ConnRequest{
		PendingConn: netio.NopPendingConn(c),
		Addr:        pc.LocalConnAddr(),
		Username:    s.username,
	}, nil
}

type testFailingInnerServer struct{}

func (testFailingInnerServer) StreamServerInfo() netio.StreamServerInfo {
	return netio.StreamServerInfo{}
}

func (testFailingInnerServer) HandleStream(netio.Conn, *tslog.Logger) (netio.ConnRequest, error) {
	return netio.ConnRequest{}, errFailingInnerServer
}

var errFailingInnerServer = errors.New("failing inner server")

func TestStreamClientServer(t *testing.T) {
	t.Parallel()

	newClient := func(t *testing.T, psc *netiotest.PipeStreamClient) netio.StreamClient {
		return tlsproxy.NewProxyClient("test", psc, &tls.Config{
			Time:         testTime,
			Certificates: clientCerts,
			RootCAs:      rootCAs,
			ServerName:   serverCommonName,
		})
	}

	server := tlsproxy.NewProxyServer(testInnerServer{}, &tls.Config{
		Time:         testTime,
		Certificates: serverCerts,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    rootCAs,
	})

	netiotest.TestWrapConnStreamClientServerProceed(
		t,
		newClient,
		server,
		conn.Addr{},
		clientCommonName,
	)
}

func TestStreamClientServerUsername(t *testing.T) {
	t.Parallel()
	for _, c := range [...]struct {
		name            string
		clientTLSConfig *tls.Config
		serverTLSConfig *tls.Config
		innerUsername   string
		wantUsername    string
	}{
		{
			name: "ClientCert/InnerUsername",
			clientTLSConfig: &tls.Config{
				Time:         testTime,
				Certificates: clientCerts,
				RootCAs:      rootCAs,
				ServerName:   serverCommonName,
			},
			serverTLSConfig: &tls.Config{
				Time:         testTime,
				Certificates: serverCerts,
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    rootCAs,
			},
			innerUsername: "Maya",
			wantUsername:  "Maya",
		},
		{
			name: "ClientCert/NoInnerUsername",
			clientTLSConfig: &tls.Config{
				Time:         testTime,
				Certificates: clientCerts,
				RootCAs:      rootCAs,
				ServerName:   serverCommonName,
			},
			serverTLSConfig: &tls.Config{
				Time:         testTime,
				Certificates: serverCerts,
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    rootCAs,
			},
			innerUsername: "",
			wantUsername:  clientCommonName,
		},
		{
			name: "NoClientCert/InnerUsername",
			clientTLSConfig: &tls.Config{
				Time:       testTime,
				RootCAs:    rootCAs,
				ServerName: serverCommonName,
			},
			serverTLSConfig: &tls.Config{
				Time:         testTime,
				Certificates: serverCerts,
			},
			innerUsername: "Maya",
			wantUsername:  "Maya",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			testStreamClientServerUsername(t, c.clientTLSConfig, c.serverTLSConfig, c.innerUsername, c.wantUsername)
		})
	}
}

func testStreamClientServerUsername(
	t *testing.T,
	clientTLSConfig *tls.Config,
	serverTLSConfig *tls.Config,
	innerUsername string,
	wantUsername string,
) {
	logger := tslogtest.NewLogger(t)

	psc, ch := netiotest.NewPipeStreamClient(true)

	server := tlsproxy.NewProxyServer(testInnerServer{username: innerUsername}, serverTLSConfig)

	var wg sync.WaitGroup
	wg.Go(func() {
		var dialCount int
		for pc := range ch {
			dialCount++

			req, err := server.HandleStream(pc, logger)
			if err != nil {
				t.Errorf("server.HandleStream failed: %v", err)
			}
			if req.Username != wantUsername {
				t.Errorf("req.Username = %q, want %q", req.Username, wantUsername)
			}

			_ = pc.Close()
		}
		if dialCount != 1 {
			t.Errorf("dialCount = %d, want 1", dialCount)
		}
	})
	t.Cleanup(func() {
		_ = psc.Close()
		wg.Wait()
	})

	client := tlsproxy.NewProxyClient("test", psc, clientTLSConfig)

	clientConn, err := client.DialStream(t.Context(), conn.Addr{}, nil)
	if err != nil {
		t.Fatalf("client.DialStream failed: %v", err)
	}
	_ = clientConn.Close()
}

func TestStreamServerError(t *testing.T) {
	t.Parallel()
	for _, c := range [...]struct {
		name            string
		innerServer     netio.StreamServer
		clientTLSConfig *tls.Config
		serverTLSConfig *tls.Config
		checkClientErr  func(*testing.T, netio.Conn, error)
		checkServerErr  func(*testing.T, error)
	}{
		{
			name:        "MissingClientCert",
			innerServer: testInnerServer{},
			clientTLSConfig: &tls.Config{
				Time:       testTime,
				RootCAs:    rootCAs,
				ServerName: serverCommonName,
			},
			serverTLSConfig: &tls.Config{
				Time:         testTime,
				Certificates: serverCerts,
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    rootCAs,
			},
			checkClientErr: clientExpectNonNilErrorOrReadError,
			checkServerErr: expectNonNilError, // unexported error
		},
		{
			name:        "ServerNameMismatch",
			innerServer: testInnerServer{},
			clientTLSConfig: &tls.Config{
				Time:       testTime,
				RootCAs:    rootCAs,
				ServerName: clientCommonName,
			},
			serverTLSConfig: &tls.Config{
				Time:         testTime,
				Certificates: serverCerts,
			},
			checkClientErr: clientExpectCertificateVerificationError,
			checkServerErr: expectOpRemoteError,
		},
		{
			name:        "ClientCertBadValidity",
			innerServer: testInnerServer{},
			clientTLSConfig: &tls.Config{
				Time:         testTime,
				Certificates: clientCerts,
				RootCAs:      rootCAs,
				ServerName:   serverCommonName,
			},
			serverTLSConfig: &tls.Config{
				Time: func() time.Time {
					return testTime().Add(101 * 24 * time.Hour)
				},
				Certificates: serverCerts,
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    rootCAs,
			},
			checkClientErr: clientExpectNonNilErrorOrReadError,
			checkServerErr: expectCertificateVerificationError,
		},
		{
			name:        "ServerCertBadValidity",
			innerServer: testInnerServer{},
			clientTLSConfig: &tls.Config{
				Time: func() time.Time {
					return testTime().Add(101 * 24 * time.Hour)
				},
				Certificates: clientCerts,
				RootCAs:      rootCAs,
				ServerName:   serverCommonName,
			},
			serverTLSConfig: &tls.Config{
				Time:         testTime,
				Certificates: serverCerts,
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    rootCAs,
			},
			checkClientErr: clientExpectCertificateVerificationError,
			checkServerErr: expectOpRemoteError,
		},
		{
			name:        "ClientCertVerificationError",
			innerServer: testInnerServer{},
			clientTLSConfig: &tls.Config{
				Time:         testTime,
				Certificates: clientCerts,
				RootCAs:      rootCAs,
				ServerName:   serverCommonName,
			},
			serverTLSConfig: &tls.Config{
				Time:         testTime,
				Certificates: serverCerts,
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    x509.NewCertPool(),
			},
			checkClientErr: clientExpectNonNilErrorOrReadError,
			checkServerErr: expectCertificateVerificationError,
		},
		{
			name:        "ServerCertVerificationError",
			innerServer: testInnerServer{},
			clientTLSConfig: &tls.Config{
				Time:         testTime,
				Certificates: clientCerts,
				RootCAs:      x509.NewCertPool(),
				ServerName:   serverCommonName,
			},
			serverTLSConfig: &tls.Config{
				Time:         testTime,
				Certificates: serverCerts,
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    rootCAs,
			},
			checkClientErr: clientExpectCertificateVerificationError,
			checkServerErr: expectOpRemoteError,
		},
		{
			name:        "InnerServerError",
			innerServer: testFailingInnerServer{},
			clientTLSConfig: &tls.Config{
				Time:       testTime,
				RootCAs:    rootCAs,
				ServerName: serverCommonName,
			},
			serverTLSConfig: &tls.Config{
				Time:         testTime,
				Certificates: serverCerts,
			},
			checkClientErr: clientExpectNonNilErrorOrReadError,
			checkServerErr: func(t *testing.T, err error) {
				t.Helper()
				if err != errFailingInnerServer {
					t.Errorf("err = %v, want %v", err, errFailingInnerServer)
				}
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			testStreamServerError(
				t,
				c.innerServer,
				c.clientTLSConfig,
				c.serverTLSConfig,
				c.checkClientErr,
				c.checkServerErr,
			)
		})
	}
}

func testStreamServerError(
	t *testing.T,
	innerServer netio.StreamServer,
	clientTLSConfig *tls.Config,
	serverTLSConfig *tls.Config,
	checkClientErr func(*testing.T, netio.Conn, error),
	checkServerErr func(*testing.T, error),
) {
	logger := tslogtest.NewLogger(t)

	psc, ch := netiotest.NewPipeStreamClient(true)

	server := tlsproxy.NewProxyServer(innerServer, serverTLSConfig)

	var wg sync.WaitGroup
	wg.Go(func() {
		var dialCount int
		for pc := range ch {
			dialCount++

			_, err := server.HandleStream(pc, logger)
			checkServerErr(t, err)
			t.Logf("server.HandleStream error: %v", err)

			_ = pc.Close()
		}
		if dialCount != 1 {
			t.Errorf("dialCount = %d, want 1", dialCount)
		}
	})
	t.Cleanup(func() {
		_ = psc.Close()
		wg.Wait()
	})

	client := tlsproxy.NewProxyClient("test", psc, clientTLSConfig)

	clientConn, err := client.DialStream(t.Context(), conn.Addr{}, nil)
	checkClientErr(t, clientConn, err)
	t.Logf("client.DialStream error: %v", err)
	if err == nil {
		_ = clientConn.(*tls.Conn).NetConn().Close()
	}
}

func expectNonNilError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Error("err = nil, want non-nil error")
	}
}

func clientExpectNonNilErrorOrReadError(t *testing.T, c netio.Conn, err error) {
	t.Helper()
	if err != nil {
		return
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("c.Read did not return an error")
	} else {
		t.Logf("c.Read error: %v", err)
	}
}

func expectOpRemoteError(t *testing.T, err error) {
	t.Helper()
	e, ok := errors.AsType[*net.OpError](err)
	if !ok {
		t.Errorf("error = %v, want %T", err, e)
		return
	}
	if wantOp := "remote error"; e.Op != wantOp {
		t.Errorf("e.Op = %q, want %q", e.Op, wantOp)
	}
}

func clientExpectCertificateVerificationError(t *testing.T, _ netio.Conn, err error) {
	t.Helper()
	expectCertificateVerificationError(t, err)
}

func expectCertificateVerificationError(t *testing.T, err error) {
	t.Helper()
	if e, ok := errors.AsType[*tls.CertificateVerificationError](err); !ok {
		t.Errorf("error = %v, want %T", err, e)
	}
}
