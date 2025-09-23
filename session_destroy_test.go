package nessus

import (
	"testing"
)

func TestClient_SessionDestroy(t *testing.T) {
	tests := []struct {
		name    string
		options []Option
		wantErr bool
	}{
		{
			name: "success token",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("64242f4c8e188e9915b710dd19fc7f260389f8af3783ee33"),
			},
			wantErr: false,
		},
		{
			name: "success apikeys",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"ede55bc4fbad66a41a46f4a5ff35500e7485adae1bc5d94d98e9a1c1f7bb0ecc",
					"af2ca8def3fa67705e38ded764d3c282fb7f82a516883bb4f1e310aba02f1e1b",
				),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(tt.options...)
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
			}

			if err := c.SessionDestroy(); (err != nil) != tt.wantErr {
				t.Errorf("SessionDestroy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
