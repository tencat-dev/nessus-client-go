package nessus

import (
	"testing"
)

func TestClient_ScansHostDetails(t *testing.T) {
	tests := []struct {
		name      string
		options   []Option
		pathParam *ScansHostDetailsPathParams
		query     *ScansHostDetailsQuery
		wantErr   bool
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
			pathParam: &ScansHostDetailsPathParams{ScanID: 1, HostID: 100},
			query:     &ScansHostDetailsQuery{HistoryID: 0},
			wantErr:   false,
		},
		{
			name: "success with valid session token",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("06b2f2a7c5b7cf2c7bee97971f8e7393d06dc0ff7b982c6f"),
			},
			pathParam: &ScansHostDetailsPathParams{ScanID: 2, HostID: 200},
			query:     &ScansHostDetailsQuery{HistoryID: 0},
			wantErr:   false,
		},
		{
			name: "error with invalid API key",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey("invalid", "invalid"),
			},
			pathParam: &ScansHostDetailsPathParams{ScanID: 1, HostID: 100},
			query:     &ScansHostDetailsQuery{},
			wantErr:   true,
		},
		{
			name: "error with invalid session token",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("invalid-token"),
			},
			pathParam: &ScansHostDetailsPathParams{ScanID: 1, HostID: 100},
			query:     &ScansHostDetailsQuery{},
			wantErr:   true,
		},
		{
			name: "error with no authentication",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
			},
			pathParam: &ScansHostDetailsPathParams{ScanID: 1, HostID: 100},
			query:     &ScansHostDetailsQuery{},
			wantErr:   true,
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
			pathParam: &ScansHostDetailsPathParams{ScanID: -1, HostID: 100},
			query:     &ScansHostDetailsQuery{},
			wantErr:   true,
		},
		{
			name: "error with negative host ID",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
					"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
				),
			},
			pathParam: &ScansHostDetailsPathParams{ScanID: 1, HostID: -100},
			query:     &ScansHostDetailsQuery{},
			wantErr:   true,
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
			pathParam: &ScansHostDetailsPathParams{ScanID: 0, HostID: 100},
			query:     &ScansHostDetailsQuery{},
			wantErr:   true,
		},
		{
			name: "error with zero host ID",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
					"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
				),
			},
			pathParam: &ScansHostDetailsPathParams{ScanID: 1, HostID: 0},
			query:     &ScansHostDetailsQuery{},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(tt.options...)
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}
			got, err := c.ScansHostDetails(tt.pathParam, tt.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScansHostDetails() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Errorf("ScansHostDetails() got = %v, want non-nil", got)
			}
		})
	}
}
