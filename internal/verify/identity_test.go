package verify

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 本文件专测"从证书 OID 提取身份"这一层的正确性。
//
// 这是 H1 的修复核心：策略判定的依据必须是签名证书里的扩展，
// 而不是 payload 自述的 builder 字符串。因此每个测试都围绕一件事：
// 无论 payload 怎么写，提取出来的身份只由证书决定。

func realBundlePath(t *testing.T) string {
	t.Helper()
	p := filepath.Join(findRepoRoot(t), "testdata", "bundle-provenance.json")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("test bundle not available: %v", err)
	}
	return p
}

func loadRealBundle(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(realBundlePath(t))
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	return b
}

// TestExtractIdentityFromBundle_RealCert 用真实 Fulcio 证书验证全部字段。
//
// 这个证书是 2023 年签发的，字段落在旧编号 arc 57264.1.x 下，
// 没有 57264.2 / .4 / .5 / .6 / .8。如果实现只认新编号，
// 这里会全部拿到空串——所以本测试同时是"新旧编号兼容"的回归门。
func TestExtractIdentityFromBundle_RealCert(t *testing.T) {
	id, err := ExtractIdentityFromBundle(loadRealBundle(t))
	if err != nil {
		t.Fatalf("extract identity: %v", err)
	}

	want := VerifiedIdentity{
		Issuer:           "https://token.actions.githubusercontent.com",
		BuildSignerURI:   "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main",
		SourceRepoURI:    "https://github.com/sigstore/sigstore-js",
		SourceRepoDigest: "dae8bd8eb433a4147b4655c00fe73e0f22bc0fb1",
		BuildConfigURI:   "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main",
		RunnerEnv:        "github-hosted",
	}

	if id.Issuer != want.Issuer {
		t.Errorf("Issuer = %q, want %q", id.Issuer, want.Issuer)
	}
	if id.BuildSignerURI != want.BuildSignerURI {
		t.Errorf("BuildSignerURI = %q, want %q", id.BuildSignerURI, want.BuildSignerURI)
	}
	if id.SourceRepoURI != want.SourceRepoURI {
		t.Errorf("SourceRepoURI = %q, want %q", id.SourceRepoURI, want.SourceRepoURI)
	}
	if id.SourceRepoDigest != want.SourceRepoDigest {
		t.Errorf("SourceRepoDigest = %q, want %q", id.SourceRepoDigest, want.SourceRepoDigest)
	}
	if id.BuildConfigURI != want.BuildConfigURI {
		t.Errorf("BuildConfigURI = %q, want %q", id.BuildConfigURI, want.BuildConfigURI)
	}
	if id.RunnerEnv != want.RunnerEnv {
		t.Errorf("RunnerEnv = %q, want %q", id.RunnerEnv, want.RunnerEnv)
	}
}

// TestExtractIdentityFromBundle_MissingChain 验证没有证书链时拒绝。
func TestExtractIdentityFromBundle_MissingChain(t *testing.T) {
	cases := map[string]string{
		"empty object":        `{}`,
		"no verification":     `{"mediaType":"x"}`,
		"empty chain":         `{"verificationMaterial":{"x509CertificateChain":{"certificates":[]}}}`,
		"empty rawBytes":      `{"verificationMaterial":{"x509CertificateChain":{"certificates":[{"rawBytes":""}]}}}`,
		"rawBytes not b64":    `{"verificationMaterial":{"x509CertificateChain":{"certificates":[{"rawBytes":"@@@"}]}}}`,
		"rawBytes not a cert": `{"verificationMaterial":{"x509CertificateChain":{"certificates":[{"rawBytes":"aGVsbG8="}]}}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			id, err := ExtractIdentityFromBundle([]byte(body))
			if err == nil {
				t.Fatalf("expected error, got identity %+v", id)
			}
			if !errors.Is(err, ErrSignatureInvalid) {
				t.Errorf("expected ErrSignatureInvalid, got %v", err)
			}
			if id != nil {
				t.Errorf("must not return identity on error, got %+v", id)
			}
		})
	}
}

// TestExtractIdentity_NoFulcioExtensions 验证证书里没有任何 Fulcio 扩展时拒绝。
//
// 这是安全关键路径：如果这种证书被放行，后续策略会因为"字段全空"而
// 要么误判为 L1 拒绝，要么在配置宽松时误放行。必须在这里就拦死。
func TestExtractIdentity_NoFulcioExtensions(t *testing.T) {
	der := makeSelfSignedCert(t, nil)

	id, err := extractVerifiedIdentity(der)
	if err == nil {
		t.Fatalf("expected error for cert without Fulcio extensions, got %+v", id)
	}
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("expected ErrSignatureInvalid, got %v", err)
	}
}

// TestExtractIdentity_OIDMissingIsRejected 是本修复最核心的负向测试：
// 证书带部分 Fulcio 扩展但缺少构建者相关字段时，必须拒绝而不是放行。
func TestExtractIdentity_OIDMissingIsRejected(t *testing.T) {
	// 只有一个无关的 Fulcio 扩展（57264.1.2 = event name），
	// 没有任何身份字段。旧实现在这种情况下会拿到全空身份并交给策略，
	// 新实现必须在提取层就拒绝。
	ext := []pkix.Extension{
		{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 2},
			Value: derUTF8("push"),
		},
	}
	der := makeSelfSignedCert(t, ext)

	_, err := extractVerifiedIdentity(der)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid when identity OIDs are absent, got %v", err)
	}
}

// TestExtractIdentity_LegacyAndModernOIDs 验证新旧两套编号都能解析。
//
// 现实中 Fulcio 证书跨两代编号格式，只支持一套会让另一代全部被误拒。
func TestExtractIdentity_LegacyAndModernOIDs(t *testing.T) {
	t.Run("legacy arc 57264.1.x", func(t *testing.T) {
		ext := []pkix.Extension{
			{Id: oidIssuer, Value: derUTF8("https://token.actions.githubusercontent.com")},
			{Id: oidBuildSignerURIOld, Value: derUTF8("https://github.com/o/r/.github/workflows/b.yml@refs/heads/main")},
			{Id: oidSourceRepoURIOld, Value: derUTF8("https://github.com/o/r")},
			{Id: oidSourceRepoDigestOld, Value: derUTF8("deadbeef")},
			{Id: oidBuildConfigURIOld, Value: derUTF8("https://github.com/o/r/.github/workflows/b.yml@refs/heads/main")},
			{Id: oidRunnerEnvOld, Value: derUTF8("github-hosted")},
		}
		id, err := extractVerifiedIdentity(makeSelfSignedCert(t, ext))
		if err != nil {
			t.Fatalf("extract: %v", err)
		}
		if id.SourceRepoURI != "https://github.com/o/r" {
			t.Errorf("SourceRepoURI = %q", id.SourceRepoURI)
		}
		if id.RunnerEnv != "github-hosted" {
			t.Errorf("RunnerEnv = %q", id.RunnerEnv)
		}
		if id.SLSALevel() != SLSALevel3 {
			t.Errorf("SLSALevel = %d, want 3", id.SLSALevel())
		}
	})

	t.Run("modern arc 57264.x", func(t *testing.T) {
		ext := []pkix.Extension{
			{Id: oidIssuerV2, Value: derUTF8("https://token.actions.githubusercontent.com")},
			{Id: oidBuildSignerURI, Value: derUTF8("https://github.com/o/r/.github/workflows/b.yml@refs/heads/main")},
			{Id: oidSourceRepoURI, Value: derUTF8("https://github.com/o/r")},
			{Id: oidSourceRepoDigest, Value: derUTF8("deadbeef")},
			{Id: oidBuildConfigURI, Value: derUTF8("https://github.com/o/r/.github/workflows/b.yml@refs/heads/main")},
			{Id: oidRunnerEnv, Value: derUTF8("github-hosted")},
		}
		id, err := extractVerifiedIdentity(makeSelfSignedCert(t, ext))
		if err != nil {
			t.Fatalf("extract: %v", err)
		}
		if id.SourceRepoURI != "https://github.com/o/r" {
			t.Errorf("SourceRepoURI = %q", id.SourceRepoURI)
		}
		if id.SLSALevel() != SLSALevel3 {
			t.Errorf("SLSALevel = %d, want 3", id.SLSALevel())
		}
	})
}

// TestExtractIdentity_PayloadCannotForgeIdentity 是 H1 的攻击场景回归测试。
//
// 场景：攻击者构造一个 payload，里面把 builder 写成合法值（欺骗旧实现），
// 但真正签名的证书来自一个不同的、不受信任的 workflow。
// 提取出的身份必须完全来自证书，payload 一个字都不能影响结果。
func TestExtractIdentity_PayloadCannotForgeIdentity(t *testing.T) {
	bundle := loadRealBundle(t)

	// 把 payload 里的 builder 改成"合法"值。
	// 注意签名会因此失效——本测试只关心提取层读的是证书还是 payload。
	forged := forgePayloadBuilder(t, bundle, "https://github.com/actions/runner")

	id, err := ExtractIdentityFromBundle(forged)
	if err != nil {
		t.Fatalf("extract identity from forged payload: %v", err)
	}

	// 身份必须仍然是证书里的真实签名者，与 payload 内容无关。
	if id.SourceRepoURI == "https://github.com/actions/runner" {
		t.Fatal("identity was taken from payload, certificate OIDs were ignored")
	}
	if id.BuildSignerURI != "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main" {
		t.Errorf("BuildSignerURI = %q, want the certificate's value", id.BuildSignerURI)
	}
}

// TestSLSALevel_Rules 逐条覆盖确认过的判定规则。
func TestSLSALevel_Rules(t *testing.T) {
	const bc = "https://github.com/o/r/.github/workflows/b.yml@refs/heads/main"

	cases := []struct {
		name    string
		id      *VerifiedIdentity
		want    int
		comment string
	}{
		{"github-hosted + build config", &VerifiedIdentity{RunnerEnv: RunnerEnvGitHubHosted, BuildConfigURI: bc}, 3,
			"平台托管运行器 + 声明式构建配置 = L3"},
		{"github-hosted no build config", &VerifiedIdentity{RunnerEnv: RunnerEnvGitHubHosted}, 2,
			"没有构建配置声明，无法证明过程被定义，降为 L2"},
		{"self-hosted + build config", &VerifiedIdentity{RunnerEnv: RunnerEnvSelfHosted, BuildConfigURI: bc}, 2,
			"自托管运行器由构建方控制，封顶 L2"},
		{"self-hosted no build config", &VerifiedIdentity{RunnerEnv: RunnerEnvSelfHosted}, 2,
			"自托管一律 L2"},
		{"empty runner + build config", &VerifiedIdentity{BuildConfigURI: bc}, 2,
			"无 runner 信息但有构建配置 = L2"},
		{"empty runner no build config", &VerifiedIdentity{}, 1,
			"什么证据都没有 = L1"},
		{"unknown runner + build config", &VerifiedIdentity{RunnerEnv: "some-ci", BuildConfigURI: bc}, 2,
			"未知运行器按无 runner 处理"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.id.SLSALevel(); got != c.want {
				t.Errorf("SLSALevel = %d, want %d (%s)", got, c.want, c.comment)
			}
		})
	}

	if got := (*VerifiedIdentity)(nil).SLSALevel(); got != 0 {
		t.Errorf("nil identity SLSALevel = %d, want 0", got)
	}
}

// TestDecodeFulcioExtensionValue 覆盖两种编码形式。
func TestDecodeFulcioExtensionValue(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{"der wrapped utf8string", derUTF8("github-hosted"), "github-hosted"},
		{"bare utf8 string", []byte("github-hosted"), "github-hosted"},
		{"der wrapped empty", []byte{0x0c, 0x00}, ""},
		{"long value", derUTF8("https://github.com/sigstore/sigstore-js/actions/runs/4735384265/attempts/1"),
			"https://github.com/sigstore/sigstore-js/actions/runs/4735384265/attempts/1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := decodeFulcioExtensionValue(c.raw)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}

	if _, err := decodeFulcioExtensionValue(nil); err == nil {
		t.Error("empty value must error")
	}
}

// TestIssuerPreference 验证新旧 issuer OID 同时存在时优先新编号。
func TestIssuerPreference(t *testing.T) {
	ext := []pkix.Extension{
		{Id: oidIssuer, Value: derUTF8("old-issuer")},
		{Id: oidIssuerV2, Value: derUTF8("new-issuer")},
		{Id: oidBuildSignerURI, Value: derUTF8("https://example.com/w.yml")},
	}
	id, err := extractVerifiedIdentity(makeSelfSignedCert(t, ext))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if id.Issuer != "new-issuer" {
		t.Errorf("Issuer = %q, want new-issuer (V2 OID takes precedence)", id.Issuer)
	}
}

// --- 测试辅助 ---

// derUTF8 把字符串编成 DER UTF8String，模拟 Fulcio 的封装方式。
func derUTF8(str string) []byte {
	b, err := asn1.Marshal(str)
	if err != nil {
		panic(err)
	}
	return b
}

// makeSelfSignedCert 生成一张带指定扩展的自签证书，返回 DER。
// 只需扩展能被 x509 解析，不需要真的可信。
func makeSelfSignedCert(t *testing.T, exts []pkix.Extension) []byte {
	t.Helper()

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Unix(1600000000, 0),
		NotAfter:              time.Unix(1900000000, 0),
		BasicConstraintsValid: true,
		ExtraExtensions:       exts,
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return der
}

// forgePayloadBuilder 改写 bundle 里 DSSE payload 的 builder 字段，
// 模拟"攻击者把 payload 自述值写成合法值"。
//
// 注意：改写后签名必然失效，本函数只用于验证提取层不读 payload，
// 不用于模拟"签名仍然有效"的场景（那种攻击需要私钥）。
func forgePayloadBuilder(t *testing.T, bundleJSON []byte, newBuilder string) []byte {
	t.Helper()

	var raw map[string]any
	if err := json.Unmarshal(bundleJSON, &raw); err != nil {
		t.Fatalf("parse bundle: %v", err)
	}
	dsse, ok := raw["dsseEnvelope"].(map[string]any)
	if !ok {
		t.Fatal("bundle has no dsseEnvelope")
	}
	payloadB64, ok := dsse["payload"].(string)
	if !ok {
		t.Fatal("dsseEnvelope has no payload")
	}
	payload, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	// 在 payload 的 JSON 里把 builder id 换成 newBuilder。
	var prov map[string]any
	if err := json.Unmarshal(payload, &prov); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	pred, _ := prov["predicate"].(map[string]any)
	if pred == nil {
		// in-toto v0.2 结构的 builder 在 predicate.builder 下。
		pred = map[string]any{}
		prov["predicate"] = pred
	}
	builder, _ := pred["builder"].(map[string]any)
	if builder == nil {
		builder = map[string]any{}
		pred["builder"] = builder
	}
	builder["id"] = newBuilder

	newPayload, err := json.Marshal(prov)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	dsse["payload"] = base64.StdEncoding.EncodeToString(newPayload)

	out, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	return out
}
