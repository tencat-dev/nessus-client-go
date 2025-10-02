package nessus

import (
	"testing"
)

func TestClient_ScansCreate(t *testing.T) {
	tests := []struct {
		name    string
		options []Option
		request *ScansCreateRequest
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
			request: &ScansCreateRequest{
				TemplateUUID: "b8cb1f88-3688-4085-b145-82f5e4ca04cf",
				Settings: &ScansCreateSetting{
					Name:        "API Key Scan",
					Description: "Scan created with API key",
					FolderID:    "2",
					PolicyID:    "1",
					TextTargets: "sv.haui.edu.vn",
				},
			},
			wantErr: false,
		},
		{
			name: "success with valid session token",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("06b2f2a7c5b7cf2c7bee97971f8e7393d06dc0ff7b982c6f"),
			},
			request: &ScansCreateRequest{
				TemplateUUID: "b32eb026-2288-4db3-abbd-081934e5144d",
				Settings: &ScansCreateSetting{
					Name:        "Token Scan",
					Description: "Scan created with token",
					FolderID:    "3",
					PolicyID:    "2",
					TextTargets: "yoasobi.com",
				},
			},
			wantErr: false,
		},
		{
			name: "error with invalid API key",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey("invalid", "invalid"),
			},
			request: &ScansCreateRequest{
				TemplateUUID: "invalid-api-key",
				Settings: &ScansCreateSetting{
					Name:        "Invalid Key",
					FolderID:    "2",
					PolicyID:    "1",
					TextTargets: "192.168.1.1",
				},
			},
			wantErr: true,
		},
		{
			name: "error with invalid session token",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("invalid-token"),
			},
			request: &ScansCreateRequest{
				TemplateUUID: "invalid-token",
				Settings: &ScansCreateSetting{
					Name:        "Invalid Token",
					FolderID:    "2",
					PolicyID:    "1",
					TextTargets: "192.168.1.1",
				},
			},
			wantErr: true,
		},
		{
			name: "error with no authentication",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
			},
			request: &ScansCreateRequest{
				TemplateUUID: "no-auth",
				Settings: &ScansCreateSetting{
					Name:        "No Auth",
					FolderID:    "2",
					PolicyID:    "1",
					TextTargets: "192.168.1.1",
				},
			},
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
			request: nil,
			wantErr: true,
		},
		{
			name: "error with empty request",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
					"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
				),
			},
			request: &ScansCreateRequest{},
			wantErr: true,
		},
		{
			name: "error with invalid scan parameters",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
					"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
				),
			},
			request: &ScansCreateRequest{
				TemplateUUID: "invalid-params",
				Settings: &ScansCreateSetting{
					Name:        "",
					FolderID:    "-1",
					PolicyID:    "not-a-number",
					TextTargets: "",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(tt.options...)
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}
			got, err := c.ScansCreate(tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScansCreate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && (got == nil || got.Scan == nil) {
				t.Errorf("ScansCreate() got = %v, want non-nil ScanResult", got)
			}
		})
	}
}
