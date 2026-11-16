package attest

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestInferSLSALevel(t *testing.T) {
	const slsaV1 = "https://slsa.dev/provenance/v1"

	tests := []struct {
		name      string
		buildType string
		builder   string
		want      int
	}{
		{"slsa v1 + github actions → L3", slsaV1, "https://github.com/actions/runner", 3},
		{"slsa v1 + gcb → L3", slsaV1, "https://cloudbuild.googleapis.com/GoogleHostedWorker", 3},
		{"slsa v1 + tekton → L3", slsaV1, "https://tekton.dev/chains/v2", 3},
		{"slsa v1 + unknown builder → L2", slsaV1, "https://unknown.example.com", 2},
		{"non-slsa build type → L1", "https://other.dev", "https://github.com/actions/runner", 1},
		{"empty → L1", "", "", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inferSLSALevel(tt.buildType, tt.builder); got != tt.want {
				t.Errorf("inferSLSALevel(%q, %q) = %d, want %d",
					tt.buildType, tt.builder, got, tt.want)
			}
		})
	}
}

func TestIsAttestationType(t *testing.T) {
	tests := []struct {
		name string
		desc v1.Descriptor
		want bool
	}{
		{
			name: "artifactType 是 in-toto",
			// ArtifactType 字段类型是 string，不是 types.MediaType
			desc: v1.Descriptor{ArtifactType: "application/vnd.in-toto+json"},
			want: true,
		},
		{
			name: "mediaType 包含 in-toto",
			// MediaType 字段类型是 types.MediaType
			desc: v1.Descriptor{MediaType: types.MediaType("application/vnd.in-toto+json")},
			want: true,
		},
		{
			name: "annotation 标识 in-toto",
			desc: v1.Descriptor{Annotations: map[string]string{
				"org.opencontainers.artifact.type": "application/vnd.in-toto+json",
			}},
			want: true,
		},
		{
			name: "普通 OCI image",
			desc: v1.Descriptor{MediaType: types.OCIManifestSchema1},
			want: false,
		},
		{
			name: "空 descriptor",
			desc: v1.Descriptor{},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAttestationType(tt.desc); got != tt.want {
				t.Errorf("isAttestationType() = %v, want %v", got, tt.want)
			}
		})
	}
}
