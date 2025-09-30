package nessus

import (
	"testing"
)

func TestClient_SessionPassword(t *testing.T) {
	tests := []struct {
		name    string
		options []Option
		req     *SessionPasswordRequest
		wantErr bool
	}{
		{
			name: "success with token",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("065954a9a9fc43d3b964c1755e036367424a0ade6005aa6c"),
			},
			req: &SessionPasswordRequest{
				Password:        "123456aA",
				CurrentPassword: "Abcd1234",
			},
			wantErr: false,
		},
		{
			name: "success with api keys",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
					"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
				),
			},
			req: &SessionPasswordRequest{
				Password:        "123456aA",
				CurrentPassword: "Abcd1234",
			},
			wantErr: false,
		},
		{
			name: "error with invalid credentials",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("invalid_token"),
			},
			req: &SessionPasswordRequest{
				Password:        "123456aA",
				CurrentPassword: "Abcd1234",
			},
			wantErr: true,
		},
		{
			name: "error with empty password",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("065954a9a9fc43d3b964c1755e036367424a0ade6005aa6c"),
			},
			req: &SessionPasswordRequest{
				Password:        "",
				CurrentPassword: "Abcd1234",
			},
			wantErr: true,
		},
		{
			name: "error with empty current password",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("065954a9a9fc43d3b964c1755e036367424a0ade6005aa6c"),
			},
			req: &SessionPasswordRequest{
				Password:        "123456aA",
				CurrentPassword: "",
			},
			wantErr: true,
		},
		{
			name: "error with no authentication",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
			},
			req: &SessionPasswordRequest{
				Password:        "123456aA",
				CurrentPassword: "Abcd1234",
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

			if err := c.SessionPassword(tt.req); (err != nil) != tt.wantErr {
				t.Errorf("SessionPassword() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				c.SessionPassword(&SessionPasswordRequest{
					Password:        "Abcd1234",
					CurrentPassword: "123456aA",
				})
			}
		})
	}
}
