package nessus

import (
	"testing"

	"github.com/bytedance/sonic"
)

func TestClient_ScansDetails(t *testing.T) {
	tests := []struct {
		name    string
		options []Option
		scanID  int
		query   *ScansDetailsQuery
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
			query:   &ScansDetailsQuery{HistoryID: 0, Limit: 0},
			wantErr: false,
		},
		{
			name: "success with valid session token",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("06b2f2a7c5b7cf2c7bee97971f8e7393d06dc0ff7b982c6f"),
			},
			scanID:  2,
			query:   &ScansDetailsQuery{HistoryID: 0, Limit: 0},
			wantErr: false,
		},
		{
			name: "error with invalid API key",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey("invalid", "invalid"),
			},
			scanID:  1,
			query:   &ScansDetailsQuery{},
			wantErr: true,
		},
		{
			name: "error with invalid session token",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("invalid-token"),
			},
			scanID:  1,
			query:   &ScansDetailsQuery{},
			wantErr: true,
		},
		{
			name: "error with no authentication",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
			},
			scanID:  1,
			query:   &ScansDetailsQuery{},
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
			query:   &ScansDetailsQuery{},
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
			query:   &ScansDetailsQuery{},
			wantErr: true,
		},
		{
			name: "error with large scan ID",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
					"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
				),
			},
			scanID:  999999999,
			query:   &ScansDetailsQuery{},
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
			got, err := c.ScansDetails(tt.scanID, tt.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScansDetails() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Errorf("ScansDetails() got = %v, want non-nil", got)
			}
		})
	}
}

func TestScansDetails_DecodesFlexibleScanEnd(t *testing.T) {
	tests := []struct {
		name string
		json string
		want FlexibleInt
	}{
		{
			name: "unix timestamp",
			json: `{"info":{"scan_end":1788685557}}`,
			want: 1788685557,
		},
		{
			name: "numeric string",
			json: `{"info":{"scan_end":"1788685557"}}`,
			want: 1788685557,
		},
		{
			name: "ctime string",
			json: `{"info":{"scan_end":"Sun Sep  6 09:05:57 2026"}}`,
			want: 1788685557,
		},
		{
			name: "null",
			json: `{"info":{"scan_end":null}}`,
			want: 0,
		},
		{
			name: "unparseable string",
			json: `{"info":{"scan_end":"bogus"}}`,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d ScansDetailsResponse
			if err := sonic.Unmarshal([]byte(tt.json), &d); err != nil {
				t.Fatalf("sonic.Unmarshal: %v", err)
			}
			if d.Info == nil {
				t.Fatal("nil Info")
			}
			if d.Info.ScanEnd != tt.want {
				t.Errorf("ScanEnd = %d, want %d", d.Info.ScanEnd, tt.want)
			}
		})
	}
}

func TestFlexibleInt_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		json string
		want FlexibleInt
	}{
		{"number", `42`, 42},
		{"numeric string", `"42"`, 42},
		{"ctime", `"Sun Sep  6 09:05:57 2026"`, 1788685557},
		{"null", `null`, 0},
		{"garbage", `"nope"`, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fi FlexibleInt
			err := sonic.Unmarshal([]byte(tt.json), &fi)
			if err != nil {
				t.Fatalf("sonic.Unmarshal: %v", err)
			}
			if fi != tt.want {
				t.Errorf("FlexibleInt = %d, want %d", fi, tt.want)
			}
		})
	}
}
