package tls

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

// newTestUConnWithSessionCache returns a HelloCustom UConn whose config has a
// session cache, which is what the session controller requires before it will
// load a ticket from it. The random source is left at the default so separate
// assemblies do not draw identical random session_ids.
func newTestUConnWithSessionCache(t *testing.T) *UConn {
	t.Helper()
	config := &Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		ClientSessionCache: NewLRUClientSessionCache(4),
		Time:               testTime,
	}
	return UClient(&net.TCPConn{}, config, HelloCustom)
}

// seedTLS12Session stores a resumable TLS 1.2 session under the cache key the
// connection will look up, so the next BuildHandshakeState loads its ticket.
func seedTLS12Session(t *testing.T, uconn *UConn, ticket []byte) {
	t.Helper()

	leaf := testECDSAP256Cert.Leaf
	uconn.config.ClientSessionCache.Put(uconn.clientSessionCacheKey(), &ClientSessionState{
		session: &SessionState{
			version:          VersionTLS12,
			cipherSuite:      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			createdAt:        uint64(uconn.config.time().Unix()),
			secret:           bytes.Repeat([]byte{1}, 48),
			extMasterSecret:  true,
			peerCertificates: []*x509.Certificate{leaf},
			verifiedChains:   [][]*x509.Certificate{{leaf}},
			ticket:           ticket,
		},
	})
}

// declaredSessionIDSpec is a minimal TLS 1.2 spec declaring the sha256 policy.
func declaredSessionIDSpec(policy func(ticket []byte) [32]byte) *ClientHelloSpec {
	return &ClientHelloSpec{
		TLSVersMin:         VersionTLS10,
		TLSVersMax:         VersionTLS12,
		CipherSuites:       []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		CompressionMethods: []uint8{compressionNone},
		Extensions: []TLSExtension{
			&SNIExtension{},
			&SessionTicketExtension{},
			&ExtendedMasterSecretExtension{},
			&SupportedCurvesExtension{Curves: []CurveID{X25519, CurveP256}},
			&SupportedPointsExtension{SupportedPoints: []byte{pointFormatUncompressed}},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{PSSWithSHA256, PKCS1WithSHA256}},
			&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
		},
		GetSessionID: policy,
	}
}

// A declared policy must be honored: with a ticket present, the session_id must
// be the policy's digest of that ticket, and therefore stable across two
// independent spec applications rather than freshly random each time.
func TestDeclaredSessionIDPolicyApplies(t *testing.T) {
	ticket := []byte("ticket-used-for-session-id-derivation")

	sessionIDs := make([][]byte, 2)
	for i := range sessionIDs {
		uconn := newTestUConnWithSessionCache(t)
		if err := uconn.ApplyPreset(declaredSessionIDSpec(sha256.Sum256)); err != nil {
			t.Fatalf("ApplyPreset #%d failed: %v", i, err)
		}
		seedTLS12Session(t, uconn, ticket)
		if err := uconn.BuildHandshakeState(); err != nil {
			t.Fatalf("BuildHandshakeState #%d failed: %v", i, err)
		}
		if !bytes.Equal(uconn.HandshakeState.Hello.SessionTicket, ticket) {
			t.Fatalf("expected the seeded ticket to be loaded into the ClientHello, got %x", uconn.HandshakeState.Hello.SessionTicket)
		}
		sessionIDs[i] = append([]byte(nil), uconn.HandshakeState.Hello.SessionId...)
	}

	want := sha256.Sum256(ticket)
	if !bytes.Equal(sessionIDs[0], want[:]) {
		t.Errorf("session_id = %x, want sha256(ticket) = %x", sessionIDs[0], want[:])
	}
	if !bytes.Equal(sessionIDs[0], sessionIDs[1]) {
		t.Errorf("declared policy must be deterministic across assemblies: got %x and %x", sessionIDs[0], sessionIDs[1])
	}
}

// The random fallback must still apply when the policy is declared but no
// ticket is available. Two assemblies must then differ, and must not equal the
// digest of an absent ticket.
func TestDeclaredSessionIDPolicyNilFallback(t *testing.T) {
	sessionIDs := make([][]byte, 2)
	for i := range sessionIDs {
		uconn := newTestUConnWithSessionCache(t)
		if err := uconn.ApplyPreset(declaredSessionIDSpec(sha256.Sum256)); err != nil {
			t.Fatalf("ApplyPreset #%d failed: %v", i, err)
		}
		// No session is seeded, so there is no ticket to derive from.
		if err := uconn.BuildHandshakeState(); err != nil {
			t.Fatalf("BuildHandshakeState #%d failed: %v", i, err)
		}
		if len(uconn.HandshakeState.Hello.SessionTicket) != 0 {
			t.Fatalf("expected no ticket, got %x", uconn.HandshakeState.Hello.SessionTicket)
		}
		sessionIDs[i] = append([]byte(nil), uconn.HandshakeState.Hello.SessionId...)
	}

	if len(sessionIDs[0]) != 32 {
		t.Fatalf("expected a 32-byte random session_id, got %d bytes", len(sessionIDs[0]))
	}
	if bytes.Equal(sessionIDs[0], sessionIDs[1]) {
		t.Errorf("nil-ticket fallback must be random, but both assemblies produced %x", sessionIDs[0])
	}
	emptyDigest := sha256.Sum256(nil)
	if bytes.Equal(sessionIDs[0], emptyDigest[:]) || bytes.Equal(sessionIDs[1], emptyDigest[:]) {
		t.Error("nil-ticket fallback must not evaluate the policy over an empty ticket")
	}
}

// A spec that never declares GetSessionID must keep the pre-existing random
// behavior, even when a ticket is loaded.
func TestUndeclaredSessionIDPolicyStaysRandom(t *testing.T) {
	ticket := []byte("ticket-that-must-be-ignored")

	sessionIDs := make([][]byte, 2)
	for i := range sessionIDs {
		uconn := newTestUConnWithSessionCache(t)
		if err := uconn.ApplyPreset(declaredSessionIDSpec(nil)); err != nil {
			t.Fatalf("ApplyPreset #%d failed: %v", i, err)
		}
		seedTLS12Session(t, uconn, ticket)
		if err := uconn.BuildHandshakeState(); err != nil {
			t.Fatalf("BuildHandshakeState #%d failed: %v", i, err)
		}
		sessionIDs[i] = append([]byte(nil), uconn.HandshakeState.Hello.SessionId...)
	}

	if !bytes.Equal(sessionIDs[0], sessionIDs[1]) && len(sessionIDs[0]) == 32 {
		return // random values differ, as expected
	}
	t.Errorf("undeclared policy must stay random: got %x and %x", sessionIDs[0], sessionIDs[1])
}

// A TLS 1.3 resumption carries the ticket as the PSK identity label rather than
// in the session_ticket extension; the policy must derive from that label.
func TestDeclaredSessionIDPolicyTLS13PSKIdentity(t *testing.T) {
	ticket := []byte("tls13-ticket-as-psk-identity")

	uconn := newTestUConnWithSessionCache(t)
	uconn.config.MinVersion = VersionTLS13
	uconn.config.MaxVersion = VersionTLS13

	spec := go127ClientHelloSpec([]SignatureScheme{PSSWithSHA256})
	spec.Extensions = append(spec.Extensions, &UtlsPreSharedKeyExtension{})
	spec.GetSessionID = sha256.Sum256
	uconn.config.PreferSkipResumptionOnNilExtension = true
	if err := uconn.ApplyPreset(spec); err != nil {
		t.Fatalf("ApplyPreset failed: %v", err)
	}

	// Seed a TLS 1.3 session so the controller loads it as a PSK identity.
	leaf := testECDSAP256Cert.Leaf
	uconn.config.ClientSessionCache.Put(uconn.clientSessionCacheKey(), &ClientSessionState{
		session: &SessionState{
			version:          VersionTLS13,
			cipherSuite:      TLS_AES_128_GCM_SHA256,
			createdAt:        uint64(uconn.config.time().Unix()),
			useBy:            uint64(uconn.config.time().Add(time.Hour).Unix()),
			secret:           bytes.Repeat([]byte{1}, 32),
			peerCertificates: []*x509.Certificate{leaf},
			verifiedChains:   [][]*x509.Certificate{{leaf}},
			ticket:           ticket,
		},
	})
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	identities := uconn.HandshakeState.Hello.PskIdentities
	if len(identities) != 1 || !bytes.Equal(identities[0].Label, ticket) {
		t.Fatalf("expected the seeded ticket as the PSK identity label, got %#v", identities)
	}
	if len(uconn.HandshakeState.Hello.SessionTicket) != 0 {
		t.Fatal("TLS 1.3 must not also populate the session_ticket extension")
	}

	want := sha256.Sum256(ticket)
	if !bytes.Equal(uconn.HandshakeState.Hello.SessionId, want[:]) {
		t.Errorf("session_id = %x, want sha256(PSK identity label) = %x", uconn.HandshakeState.Hello.SessionId, want[:])
	}
}

// Cloning a spec must preserve the declared policy as a callable function, and
// the clone must produce the same session_id as the original spec.
func TestClonedSpecPreservesSessionIDPolicy(t *testing.T) {
	original := declaredSessionIDSpec(sha256.Sum256)
	cloned := original.clone()

	if cloned.GetSessionID == nil {
		t.Fatal("expected clone to preserve GetSessionID")
	}
	if cloned == original {
		t.Fatal("expected clone to allocate a new ClientHelloSpec")
	}

	ticket := []byte("clone-policy-parity")
	if got, want := cloned.GetSessionID(ticket), original.GetSessionID(ticket); got != want {
		t.Errorf("cloned policy result = %x, original = %x", got, want)
	}

	// Applying the clone must still honor the policy end-to-end.
	uconn := newTestUConnWithSessionCache(t)
	if err := uconn.ApplyPreset(cloned); err != nil {
		t.Fatalf("ApplyPreset failed: %v", err)
	}
	seedTLS12Session(t, uconn, ticket)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}
	want := sha256.Sum256(ticket)
	if !bytes.Equal(uconn.HandshakeState.Hello.SessionId, want[:]) {
		t.Errorf("session_id from cloned spec = %x, want %x", uconn.HandshakeState.Hello.SessionId, want[:])
	}

	// The clone must stay usable: ApplyPreset clones again internally, and the
	// policy must survive that second clone rather than degrade to nil.
	if cloned.GetSessionID == nil {
		t.Fatal("expected the session_id policy to remain on the clone after use")
	}
}

// quicSessionIDSpec is a minimal TLS 1.3 spec (QUIC requires TLS 1.3) that still
// declares the sha256 session_id policy.
func quicSessionIDSpec(t *testing.T) *ClientHelloSpec {
	t.Helper()
	spec := go127ClientHelloSpec([]SignatureScheme{PSSWithSHA256})
	spec.Extensions = append(spec.Extensions,
		&ALPNExtension{AlpnProtocols: []string{"h3"}},
		&QUICTransportParametersExtension{},
	)
	spec.GetSessionID = sha256.Sum256
	return spec
}

// QUIC connections must send a zero-length session_id (RFC 9001, Section 8.4),
// even when the applied spec declares a policy.
func TestDeclaredSessionIDPolicyQUICZeroLength(t *testing.T) {
	config := &Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		ClientSessionCache: NewLRUClientSessionCache(4),
		Time:               testTime,
	}
	client := UQUICClient(&QUICConfig{TLSConfig: config}, HelloCustom)
	if err := client.ApplyPreset(quicSessionIDSpec(t)); err != nil {
		t.Fatalf("ApplyPreset failed: %v", err)
	}

	if err := client.conn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}
	if got := client.conn.HandshakeState.Hello.SessionId; len(got) != 0 {
		t.Errorf("QUIC session_id must be zero-length, got %x", got)
	}
	if got := client.conn.getSessionID; got == nil {
		t.Error("expected the QUIC connection to still carry the declared policy")
	}
}
