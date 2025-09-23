package nessus

import (
	"testing"
)

func TestClient_ServerStatus(t *testing.T) {
	tests := []struct {
		name    string
		fields  *Client
		want    *ServerStatusResponse
		wantErr bool
	}{
		{
			name:   "call real api",
			fields: NewClient(),
			want: &ServerStatusResponse{
				Code:   200,
				Status: "ready",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				req:    tt.fields.req,
				apiURL: tt.fields.apiURL,
			}
			got, err := c.ServerStatus()
			if (err != nil) != tt.wantErr {
				t.Errorf("ServerStatus() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil {
				t.Errorf("ServerStatus() got nil response")
			}
			if got.Code != tt.want.Code {
				t.Errorf("ServerStatus() Code = %v, want %v", got.Code, tt.want.Code)
			}
			if got.Status != tt.want.Status {
				t.Errorf("ServerStatus() Status = %v, want %v", got.Status, tt.want.Status)
			}
		})
	}
}
