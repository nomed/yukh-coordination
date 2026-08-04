package primitivesceremony

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const Profile = "yukh-coordination/private-primitives-offline-ceremony-v1"

var ErrInvalid = errors.New("offline ceremony unavailable")

type configJSON struct {
	Profile     string `json:"profile"`
	ServerName  string `json:"server_name"`
	TenantID    string `json:"tenant_id"`
	PrincipalID string `json:"principal_id"`
	RootKeyID   string `json:"root_key_id"`
	PolicyKeyID string `json:"policy_key_id"`
}

type receiptJSON struct {
	LeafCertificateSHA256      string `json:"leaf_certificate_sha256"`
	LeafExpiresAt              string `json:"leaf_expires_at"`
	NATSBootstrapPolicySHA256  string `json:"nats_bootstrap_policy_sha256"`
	NATSRuntimePolicySHA256    string `json:"nats_runtime_policy_sha256"`
	PolicyExpiresAt            string `json:"policy_expires_at"`
	PolicyKeyID                string `json:"policy_key_id"`
	PolicyAlgorithm            string `json:"policy_algorithm"`
	PolicyPublicKeySHA256      string `json:"policy_public_key_sha256"`
	Profile                    string `json:"profile"`
	RegistrationTemplateSHA256 string `json:"registration_template_sha256"`
	RootExpiresAt              string `json:"root_expires_at"`
	RootKeyID                  string `json:"root_key_id"`
	TLSAlgorithm               string `json:"tls_algorithm"`
	TrustBundleSHA256          string `json:"trust_bundle_sha256"`
	FiveActionPolicySHA256     string `json:"five_action_policy_sha256"`
}

type Generator struct {
	Now     func() time.Time
	Entropy io.Reader
}

func (generator Generator) Generate(raw []byte, output string) error {
	config, err := parseConfig(raw)
	if err != nil || !exactDirectory(output) {
		return ErrInvalid
	}
	now := generator.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC().Truncate(time.Second) }
	}
	entropy := generator.Entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	issued := now()
	if issued.Location() != time.UTC || issued.Nanosecond() != 0 {
		return ErrInvalid
	}
	entries, err := generate(config, issued, entropy)
	if err != nil {
		return ErrInvalid
	}
	written := make([]string, 0, len(entries))
	for _, entry := range entries {
		path := filepath.Join(output, entry.name)
		if err := os.WriteFile(path, entry.value, entry.mode); err != nil {
			_ = os.Remove(path)
			for _, previous := range written {
				_ = os.Remove(previous)
			}
			return ErrInvalid
		}
		written = append(written, path)
	}
	return nil
}

type outputEntry struct {
	name  string
	value []byte
	mode  os.FileMode
}

func generate(config configJSON, issued time.Time, entropy io.Reader) ([]outputEntry, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), entropy)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), entropy)
	if err != nil {
		return nil, err
	}
	policyPublic, policyPrivate, err := ed25519.GenerateKey(entropy)
	if err != nil {
		return nil, err
	}
	rootSerial, err := serial(entropy)
	if err != nil {
		return nil, err
	}
	leafSerial, err := serial(entropy)
	if err != nil {
		return nil, err
	}
	rootTemplate := &x509.Certificate{SerialNumber: rootSerial, Subject: pkix.Name{CommonName: "Yukh private staging root"}, NotBefore: issued, NotAfter: issued.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature, SignatureAlgorithm: x509.ECDSAWithSHA256}
	rootDER, err := x509.CreateCertificate(entropy, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	leafTemplate := &x509.Certificate{SerialNumber: leafSerial, Subject: pkix.Name{CommonName: "Yukh private staging service"}, NotBefore: issued, NotAfter: issued.Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, SignatureAlgorithm: x509.ECDSAWithSHA256}
	if ip := net.ParseIP(config.ServerName); ip != nil {
		leafTemplate.IPAddresses = []net.IP{ip}
	} else {
		leafTemplate.DNSNames = []string{config.ServerName}
	}
	leafDER, err := x509.CreateCertificate(entropy, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	rootPrivate, _ := x509.MarshalPKCS8PrivateKey(rootKey)
	leafPrivate, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	policyPrivateDER, _ := x509.MarshalPKCS8PrivateKey(policyPrivate)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	policyPublicRaw, _ := canonical(map[string]any{"algorithm": "Ed25519", "expires_at": format(issued.Add(30 * 24 * time.Hour)), "issued_at": format(issued), "key_id": config.PolicyKeyID, "public_key": base64.RawURLEncoding.EncodeToString(policyPublic), "profile": "yukh-coordination/private-primitives-policy-key/v1"})
	actions := []string{"coordination.nonce.consume", "coordination.lease.acquire", "coordination.lease.inspect", "coordination.lease.renew", "coordination.lease.release"}
	fiveActions, _ := canonical(map[string]any{"actions": actions, "profile": "yukh-coordination/private-primitives-five-action-policy/v1"})
	registration, _ := canonical(map[string]any{"actions": actions, "dpop_thumbprint": "${DPOP_THUMBPRINT}", "expires_at": "${EXPIRES_AT}", "issued_at": "${ISSUED_AT}", "key_id": config.PolicyKeyID, "principal_id": config.PrincipalID, "profile": "yukh-coordination/private-primitives-registration/v1", "tenant_id": config.TenantID, "token_digest": "${TOKEN_DIGEST}"})
	buckets := []string{"YUKH_COORDINATION_NONCES_V1", "YUKH_COORDINATION_LEASES_V1", "YUKH_COORDINATION_CAPABILITY_BUDGET_V1"}
	bootstrapPolicy, _ := canonical(map[string]any{"buckets": buckets, "operations": []string{"create", "verify"}, "profile": "yukh-coordination/private-primitives-nats-bootstrap-policy/v1"})
	runtimePolicy, _ := canonical(map[string]any{"buckets": buckets, "operations": []string{"get", "put", "create", "update", "watch"}, "profile": "yukh-coordination/private-primitives-nats-runtime-policy/v1"})
	receipt, _ := canonical(receiptJSON{Profile: Profile, RootKeyID: config.RootKeyID, PolicyKeyID: config.PolicyKeyID, TLSAlgorithm: "ECDSA-P256-SHA256", PolicyAlgorithm: "Ed25519", RootExpiresAt: format(rootTemplate.NotAfter), LeafExpiresAt: format(leafTemplate.NotAfter), PolicyExpiresAt: format(issued.Add(30 * 24 * time.Hour)), TrustBundleSHA256: digest(rootPEM), LeafCertificateSHA256: digest(leafPEM), PolicyPublicKeySHA256: digest(policyPublicRaw), RegistrationTemplateSHA256: digest(registration), FiveActionPolicySHA256: digest(fiveActions), NATSBootstrapPolicySHA256: digest(bootstrapPolicy), NATSRuntimePolicySHA256: digest(runtimePolicy)})
	return []outputEntry{
		{"root-private.pk8.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rootPrivate}), 0o400}, {"root-cert.pem", rootPEM, 0o444},
		{"leaf-private.pk8.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafPrivate}), 0o400}, {"leaf-cert.pem", leafPEM, 0o444},
		{"policy-private.pk8.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: policyPrivateDER}), 0o400}, {"policy-public.json", policyPublicRaw, 0o444},
		{"registration-template.json", registration, 0o444}, {"five-action-policy.json", fiveActions, 0o444}, {"nats-bootstrap-policy.json", bootstrapPolicy, 0o444}, {"nats-runtime-policy.json", runtimePolicy, 0o444}, {"receipt.json", receipt, 0o444},
	}, nil
}

func Verify(output string) error {
	if !filepath.IsAbs(output) || filepath.Clean(output) != output {
		return ErrInvalid
	}
	read := func(name string) ([]byte, error) {
		value, err := os.ReadFile(filepath.Join(output, name))
		if err != nil || len(value) == 0 || len(value) > 64*1024 {
			return nil, ErrInvalid
		}
		return value, nil
	}
	receiptRaw, err := read("receipt.json")
	if err != nil {
		return ErrInvalid
	}
	canonicalReceipt, err := jsoncanonicalizer.Transform(receiptRaw)
	if err != nil || !bytes.Equal(receiptRaw, canonicalReceipt) {
		return ErrInvalid
	}
	var receipt receiptJSON
	decoder := json.NewDecoder(bytes.NewReader(receiptRaw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || receipt.Profile != Profile || receipt.TLSAlgorithm != "ECDSA-P256-SHA256" || receipt.PolicyAlgorithm != "Ed25519" {
		return ErrInvalid
	}
	files := map[string]string{"root-cert.pem": receipt.TrustBundleSHA256, "leaf-cert.pem": receipt.LeafCertificateSHA256, "policy-public.json": receipt.PolicyPublicKeySHA256, "registration-template.json": receipt.RegistrationTemplateSHA256, "five-action-policy.json": receipt.FiveActionPolicySHA256, "nats-bootstrap-policy.json": receipt.NATSBootstrapPolicySHA256, "nats-runtime-policy.json": receipt.NATSRuntimePolicySHA256}
	values := make(map[string][]byte, len(files))
	for name, expected := range files {
		value, err := read(name)
		if err != nil || digest(value) != expected {
			return ErrInvalid
		}
		values[name] = value
	}
	rootBlock, _ := pem.Decode(values["root-cert.pem"])
	leafBlock, _ := pem.Decode(values["leaf-cert.pem"])
	if rootBlock == nil || leafBlock == nil {
		return ErrInvalid
	}
	root, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil || !root.IsCA || root.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return ErrInvalid
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil || leaf.SignatureAlgorithm != x509.ECDSAWithSHA256 || leaf.CheckSignatureFrom(root) != nil || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		return ErrInvalid
	}
	for _, name := range []string{"policy-public.json", "registration-template.json", "five-action-policy.json", "nats-bootstrap-policy.json", "nats-runtime-policy.json"} {
		canonicalValue, err := jsoncanonicalizer.Transform(values[name])
		if err != nil || !bytes.Equal(values[name], canonicalValue) {
			return ErrInvalid
		}
	}
	actions := []string{"coordination.nonce.consume", "coordination.lease.acquire", "coordination.lease.inspect", "coordination.lease.renew", "coordination.lease.release"}
	expectedActions, _ := canonical(map[string]any{"actions": actions, "profile": "yukh-coordination/private-primitives-five-action-policy/v1"})
	buckets := []string{"YUKH_COORDINATION_NONCES_V1", "YUKH_COORDINATION_LEASES_V1", "YUKH_COORDINATION_CAPABILITY_BUDGET_V1"}
	expectedBootstrap, _ := canonical(map[string]any{"buckets": buckets, "operations": []string{"create", "verify"}, "profile": "yukh-coordination/private-primitives-nats-bootstrap-policy/v1"})
	expectedRuntime, _ := canonical(map[string]any{"buckets": buckets, "operations": []string{"get", "put", "create", "update", "watch"}, "profile": "yukh-coordination/private-primitives-nats-runtime-policy/v1"})
	if !bytes.Equal(values["five-action-policy.json"], expectedActions) || !bytes.Equal(values["nats-bootstrap-policy.json"], expectedBootstrap) || !bytes.Equal(values["nats-runtime-policy.json"], expectedRuntime) {
		return ErrInvalid
	}
	return nil
}

func parseConfig(raw []byte) (configJSON, error) {
	var value configJSON
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) == 0 || len(raw) > 4096 || decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF || value.Profile != Profile || !identity(value.ServerName) || !opaque(value.TenantID) || !opaque(value.PrincipalID) || !opaque(value.RootKeyID) || !opaque(value.PolicyKeyID) || value.RootKeyID == value.PolicyKeyID {
		return value, ErrInvalid
	}
	return value, nil
}

func exactDirectory(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&0o077 != 0 {
		return false
	}
	entries, err := os.ReadDir(path)
	return err == nil && len(entries) == 0
}
func identity(value string) bool {
	if ip := net.ParseIP(value); ip != nil {
		return true
	}
	if len(value) < 1 || len(value) > 253 || value != strings.ToLower(value) {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
				return false
			}
		}
	}
	return true
}
func opaque(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:-", r)) {
			return false
		}
	}
	return true
}
func serial(reader io.Reader) (*big.Int, error) {
	raw := make([]byte, 16)
	if _, err := io.ReadFull(reader, raw); err != nil {
		return nil, err
	}
	raw[0] &= 0x7f
	raw[0] |= 1
	return new(big.Int).SetBytes(raw), nil
}
func canonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return jsoncanonicalizer.Transform(raw)
}
func digest(value []byte) string    { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }
func format(value time.Time) string { return value.UTC().Format("2006-01-02T15:04:05Z") }
