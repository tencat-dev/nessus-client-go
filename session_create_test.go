package nessus

import (
	"testing"
)

func TestClient_SessionCreate(t *testing.T) {
	tests := []struct {
		name    string
		options []Option
		wantErr bool
	}{
		{
			name: "success",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAccount("admin", "Abcd1234"),
			},
			wantErr: false,
		},
		{
			name: "error",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAccount("admin", "Abcd"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(tt.options...)
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
			}

			got, err := c.SessionCreate()
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionCreate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil && got.Token == "" {
				t.Errorf("SessionCreate() got = %v", got)
			}
		})
	}
}
