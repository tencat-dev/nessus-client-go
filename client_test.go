package nessus

import (
	"testing"
)

func TestNewClient(t *testing.T) {
	type args struct {
		opts []Option
	}
	tests := []struct {
		name string
		args args
		want *Client
	}{
		{
			name: "TestSuccess",
			args: args{
				opts: []Option{
					WithAPIURL("https://localhost:8834"),
				},
			},
			want: &Client{
				apiURL: "https://localhost:8834",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := NewClient(tt.args.opts...); err != nil {
				if got.apiURL != tt.want.apiURL {
					t.Errorf("NewClient() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
