package nessus

import (
	"testing"
)

func TestClient_ServerProperties(t *testing.T) {
	tests := []struct {
		name    string
		options []Option
		want    *ServerPropertiesResponse
		wantErr bool
	}{
		{
			name: "success",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
			},
			want: &ServerPropertiesResponse{
				NessusType: "Nessus Scanner (SC)",
			},
			wantErr: false,
		},
		{
			name: "error",
			options: []Option{
				WithAPIURL("https://localhost:8835"),
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(tt.options...)
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			got, err := c.ServerProperties()
			if (err != nil) != tt.wantErr {
				t.Fatalf("ServerProperties() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.want == nil {
				return
			}

			if got == nil {
				t.Fatalf("got nil, want %+v", tt.want)
			}
			if got.NessusType != tt.want.NessusType {
				t.Errorf("NessusType got = %v, want %v", got.NessusType, tt.want.NessusType)
			}
		})
	}
}
