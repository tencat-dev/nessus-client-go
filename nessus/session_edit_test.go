package nessus

import (
	"testing"
)

func TestClient_SessionEdit(t *testing.T) {
	tests := []struct {
		name    string
		options []Option
		req     *SessionEditRequest
		want    *SessionEditResponse
		wantErr bool
	}{
		{
			name: "success",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"ede55bc4fbad66a41a46f4a5ff35500e7485adae1bc5d94d98e9a1c1f7bb0ecc",
					"af2ca8def3fa67705e38ded764d3c282fb7f82a516883bb4f1e310aba02f1e1b",
				),
			},
			req: &SessionEditRequest{
				Name: "test",
			},
			want: &SessionEditResponse{
				Name: "test",
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

			got, err := c.SessionEdit(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionEdit() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil && got.Name != tt.want.Name {
				t.Errorf("SessionEdit() got = %v, want %v", got, tt.want)
			}
		})
	}
}
