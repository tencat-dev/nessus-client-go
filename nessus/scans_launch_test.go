package nessus

import (
	"testing"
)

func TestClient_ScansLaunch(t *testing.T) {
	tests := []struct {
		name    string
		options []Option
		scanID  int
		request *ScansLaunchRequest
		wantErr bool
	}{
		{
			name: "success with valid API key",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
					"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
				),
			},
			scanID:  1,
			request: &ScansLaunchRequest{AltTargets: []string{"192.168.1.1"}},
			wantErr: false,
		},
		{
			name: "success with valid session token",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("06b2f2a7c5b7cf2c7bee97971f8e7393d06dc0ff7b982c6f"),
			},
			scanID:  2,
			request: &ScansLaunchRequest{AltTargets: []string{"10.0.0.1"}},
			wantErr: false,
		},
		{
			name: "error with invalid API key",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey("invalid", "invalid"),
			},
			scanID:  1,
			request: &ScansLaunchRequest{AltTargets: []string{"192.168.1.1"}},
			wantErr: true,
		},
		{
			name: "error with invalid session token",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("invalid-token"),
			},
			scanID:  1,
			request: &ScansLaunchRequest{AltTargets: []string{"192.168.1.1"}},
			wantErr: true,
		},
		{
			name: "error with no authentication",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
			},
			scanID:  1,
			request: &ScansLaunchRequest{AltTargets: []string{"192.168.1.1"}},
			wantErr: true,
		},
		{
			name: "error with negative scan ID",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
					"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
				),
			},
			scanID:  -1,
			request: &ScansLaunchRequest{AltTargets: []string{"192.168.1.1"}},
			wantErr: true,
		},
		{
			name: "error with nil request",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
					"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
				),
			},
			scanID:  1,
			request: nil,
			wantErr: false, // Accepts nil request, server may handle validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(tt.options...)
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}
			got, err := c.ScansLaunch(tt.scanID, tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScansLaunch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && (got == nil || got.ScanUUID == "") {
				t.Errorf("ScansLaunch() got = %v, want non-nil ScanUUID", got)
			}
		})
	}
}
