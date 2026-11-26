package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestCert 生成一张自签证书写盘，返回证书的序列号以便区分新旧。
func writeTestCert(t *testing.T, dir, cn string, serial int64) *big.Int {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	sn := big.NewInt(serial)
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{cn},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	return sn
}

func serialOf(t *testing.T, cert *tls.Certificate) int64 {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf.SerialNumber.Int64()
}

// 证书文件被替换后，GetCertificate 必须返回新证书，且无需重启。
// 这直接对应 cert-manager 续期场景：Secret 更新 -> kubelet 更新挂载
// -> 进程下一次握手即用上新证书。
func TestCertReloaderPicksUpReplacedCertificate(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	writeTestCert(t, dir, "old.example.com", 1001)
	r := newCertReloader(logger, filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))

	first, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("first GetCertificate: %v", err)
	}
	if got := serialOf(t, first); got != 1001 {
		t.Fatalf("first serial = %d, want 1001", got)
	}

	// 换成另一张证书。文件大小不同，确保 stat 能看出变化。
	writeTestCert(t, dir, "new.example.com", 2002)
	// 某些文件系统 modtime 精度较粗，显式推进时间保证 stat 能观测到变化。
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(filepath.Join(dir, "tls.crt"), future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	second, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("second GetCertificate: %v", err)
	}
	if got := serialOf(t, second); got != 2002 {
		t.Fatalf("second serial = %d, want 2002 (certificate was not reloaded)", got)
	}
}

// 证书文件损坏时必须继续返回上一份可用证书，而不是让所有握手失败。
func TestCertReloaderKeepsPreviousOnCorruption(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	writeTestCert(t, dir, "good.example.com", 3003)
	r := newCertReloader(logger, filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))

	good, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("initial GetCertificate: %v", err)
	}

	// 模拟写入过程中的中间态：cert-manager 与 kubelet 之间存在同步窗口。
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("corrupt cert: %v", err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(filepath.Join(dir, "tls.crt"), future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	after, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate after corruption must not fail: %v", err)
	}
	if got := serialOf(t, after); got != 3003 {
		t.Fatalf("serial after corruption = %d, want 3003 (previous cert must be kept)", got)
	}
	if serialOf(t, good) != 3003 {
		t.Fatalf("initial cert mutated unexpectedly")
	}
}
