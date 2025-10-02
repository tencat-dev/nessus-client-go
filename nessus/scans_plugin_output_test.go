package nessus

import (
	"testing"
)

func TestClient_ScansPluginOutput(t *testing.T) {
	tests := []struct {
		name      string
		options   []Option
		pathParam *ScansPluginOutputPathParams
		query     *ScansPluginOutputQuery
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
			pathParam: &ScansPluginOutputPathParams{ScanID: 1, HostID: 100, PluginID: 2000},
			query:     &ScansPluginOutputQuery{HistoryID: 0},
			wantErr:   false,
		},
		{
			name: "success with valid session token",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("06b2f2a7c5b7cf2c7bee97971f8e7393d06dc0ff7b982c6f"),
			},
			pathParam: &ScansPluginOutputPathParams{ScanID: 2, HostID: 200, PluginID: 3000},
			query:     &ScansPluginOutputQuery{HistoryID: 0},
			wantErr:   false,
		},
		{
			name: "error with invalid API key",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey("invalid", "invalid"),
			},
			pathParam: &ScansPluginOutputPathParams{ScanID: 1, HostID: 100, PluginID: 2000},
			query:     &ScansPluginOutputQuery{},
			wantErr:   true,
		},
		{
			name: "error with invalid session token",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("invalid-token"),
			},
			pathParam: &ScansPluginOutputPathParams{ScanID: 1, HostID: 100, PluginID: 2000},
			query:     &ScansPluginOutputQuery{},
			wantErr:   true,
		},
		{
			name: "error with no authentication",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
			},
			pathParam: &ScansPluginOutputPathParams{ScanID: 1, HostID: 100, PluginID: 2000},
			query:     &ScansPluginOutputQuery{},
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
			pathParam: &ScansPluginOutputPathParams{ScanID: -1, HostID: 100, PluginID: 2000},
			query:     &ScansPluginOutputQuery{},
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
			pathParam: &ScansPluginOutputPathParams{ScanID: 1, HostID: -100, PluginID: 2000},
			query:     &ScansPluginOutputQuery{},
			wantErr:   true,
		},
		{
			name: "error with negative plugin ID",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
					"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
				),
			},
			pathParam: &ScansPluginOutputPathParams{ScanID: 1, HostID: 100, PluginID: -2000},
			query:     &ScansPluginOutputQuery{},
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
			pathParam: &ScansPluginOutputPathParams{ScanID: 0, HostID: 100, PluginID: 2000},
			query:     &ScansPluginOutputQuery{},
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
			pathParam: &ScansPluginOutputPathParams{ScanID: 1, HostID: 0, PluginID: 2000},
			query:     &ScansPluginOutputQuery{},
			wantErr:   true,
		},
		{
			name: "error with zero plugin ID",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
					"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
				),
			},
			pathParam: &ScansPluginOutputPathParams{ScanID: 1, HostID: 100, PluginID: 0},
			query:     &ScansPluginOutputQuery{},
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
			got, err := c.ScansPluginOutput(tt.pathParam, tt.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScansPluginOutput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Errorf("ScansPluginOutput() got = %v, want non-nil", got)
			}
		})
	}
}
