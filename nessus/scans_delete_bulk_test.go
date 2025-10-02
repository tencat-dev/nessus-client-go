package nessus

import (
	"testing"
)

func TestClient_ScansDeleteBulk(t *testing.T) {
	tests := []struct {
		name    string
		options []Option
		ids     []int
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
			ids:     []int{1, 2, 3},
			wantErr: false,
		},
		{
			name: "success with valid session token",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("06b2f2a7c5b7cf2c7bee97971f8e7393d06dc0ff7b982c6f"),
			},
			ids:     []int{4, 5},
			wantErr: false,
		},
		{
			name: "error with invalid API key",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey("invalid", "invalid"),
			},
			ids:     []int{1, 2},
			wantErr: true,
		},
		{
			name: "error with invalid session token",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("invalid-token"),
			},
			ids:     []int{1, 2},
			wantErr: true,
		},
		{
			name: "error with no authentication",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
			},
			ids:     []int{1, 2},
			wantErr: true,
		},
		{
			name: "error with empty IDs",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
					"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
				),
			},
			ids:     []int{},
			wantErr: true,
		},
		{
			name: "error with negative ID",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
					"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
				),
			},
			ids:     []int{-1, 2},
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
			got, err := c.ScansDeleteBulk(tt.ids)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScansDeleteBulk() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && (got == nil || len(got.Deleted) == 0) {
				t.Errorf("ScansDeleteBulk() got = %v, want non-nil Deleted", got)
			}
		})
	}
}
