package nessus

import (
	"testing"
)

func TestClient_SessionGet(t *testing.T) {
	tests := []struct {
		name    string
		options []Option
		wantErr bool
	}{
		{
			name: "success",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("c9b2a19e062c06f58d408dc030bea4f13774aff9caf56f85"),
			},
			wantErr: false,
		},
		{
			name: "error",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
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

			got, err := c.SessionGet()
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionGet() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil {
				t.Errorf("SessionGet() got = %v", got)
			}
		})
	}
}
