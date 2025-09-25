package nessus

import (
	"reflect"
	"testing"
)

func TestClient_SessionKeys(t *testing.T) {
	tests := []struct {
		name    string
		options []Option
		req     *SessionKeysRequest
		want    *SessionKeysResponse
		wantErr bool
	}{
		{
			name: "success",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("656fead1fcaec70f40284f74f6b46660960d50071b174cc0"),
			},
			req: &SessionKeysRequest{
				AccessKey: "ede55bc4fbad66a41a46f4a5ff35500e7485adae1bc5d94d98e9a1c1f7bb0ecc",
				SecretKey: "af2ca8def3fa67705e38ded764d3c282fb7f82a516883bb4f1e310aba02f1e1b",
			},
			want: &SessionKeysResponse{
				AccessKey: "ede55bc4fbad66a41a46f4a5ff35500e7485adae1bc5d94d98e9a1c1f7bb0ecc",
				SecretKey: "af2ca8def3fa67705e38ded764d3c282fb7f82a516883bb4f1e310aba02f1e1b",
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

			got, err := c.SessionKeys(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionKeys() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SessionKeys() got = %v, want %v", got, tt.want)
			}
		})
	}
}
