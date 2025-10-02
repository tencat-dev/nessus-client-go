package nessus

import (
	"testing"
)

func TestClient_ScansSchedule(t *testing.T) {
	tests := []struct {
		name    string
		options []Option
		scanID  int
		request *ScansScheduleRequest
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
			request: &ScansScheduleRequest{Enabled: true},
			wantErr: false,
		},
		{
			name: "success with valid session token",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("06b2f2a7c5b7cf2c7bee97971f8e7393d06dc0ff7b982c6f"),
			},
			scanID:  2,
			request: &ScansScheduleRequest{Enabled: false},
			wantErr: false,
		},
		{
			name: "error with invalid API key",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey("invalid", "invalid"),
			},
			scanID:  1,
			request: &ScansScheduleRequest{Enabled: true},
			wantErr: true,
		},
		{
			name: "error with invalid session token",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("invalid-token"),
			},
			scanID:  1,
			request: &ScansScheduleRequest{Enabled: true},
			wantErr: true,
		},
		{
			name: "error with no authentication",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
			},
			scanID:  1,
			request: &ScansScheduleRequest{Enabled: true},
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
			request: &ScansScheduleRequest{Enabled: true},
			wantErr: true,
		},
		{
			name: "error with zero scan ID",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
					"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
				),
			},
			scanID:  0,
			request: &ScansScheduleRequest{Enabled: true},
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
			got, err := c.ScansSchedule(tt.scanID, tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScansSchedule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Errorf("ScansSchedule() got = %v, want non-nil", got)
			}
		})
	}
}
