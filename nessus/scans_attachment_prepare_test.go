package nessus

import (
	"testing"
)

func TestClient_ScansAttachmentPrepare(t *testing.T) {
	type args struct {
		param   *ScansAttachmentPrepareParam
		request *ScansAttachmentPrepareRequest
		options []Option
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "success_with_history_id",
			args: args{
				param: &ScansAttachmentPrepareParam{
					ScanID:       1,
					AttachmentID: 1,
				},
				request: &ScansAttachmentPrepareRequest{
					HistoryID: 123,
				},
				options: []Option{
					WithAPIURL("https://localhost:8834"),
					WithAPIKey(
						"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
						"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
					),
				},
			},
			wantErr: false,
		},
		{
			name: "success_without_history_id",
			args: args{
				param: &ScansAttachmentPrepareParam{
					ScanID:       2,
					AttachmentID: 2,
				},
				request: &ScansAttachmentPrepareRequest{},
				options: []Option{
					WithAPIURL("https://localhost:8834"),
					WithAPIKey(
						"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
						"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
					),
				},
			},
			wantErr: false,
		},
		{
			name: "error_missing_api_key",
			args: args{
				param: &ScansAttachmentPrepareParam{
					ScanID:       1,
					AttachmentID: 1,
				},
				request: &ScansAttachmentPrepareRequest{
					HistoryID: 123,
				},
				options: []Option{
					WithAPIURL("https://localhost:8834"),
				},
			},
			wantErr: true,
		},
		{
			name: "error_invalid_scan_id",
			args: args{
				param: &ScansAttachmentPrepareParam{
					ScanID:       -1,
					AttachmentID: 1,
				},
				request: &ScansAttachmentPrepareRequest{
					HistoryID: 123,
				},
				options: []Option{
					WithAPIURL("https://localhost:8834"),
					WithAPIKey(
						"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
						"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
					),
				},
			},
			wantErr: true,
		},
		{
			name: "error_invalid_attachment_id",
			args: args{
				param: &ScansAttachmentPrepareParam{
					ScanID:       1,
					AttachmentID: -1,
				},
				request: &ScansAttachmentPrepareRequest{
					HistoryID: 123,
				},
				options: []Option{
					WithAPIURL("https://localhost:8834"),
					WithAPIKey(
						"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
						"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
					),
				},
			},
			wantErr: true,
		},
		{
			name: "error_zero_scan_id",
			args: args{
				param: &ScansAttachmentPrepareParam{
					ScanID:       0,
					AttachmentID: 1,
				},
				request: &ScansAttachmentPrepareRequest{
					HistoryID: 123,
				},
				options: []Option{
					WithAPIURL("https://localhost:8834"),
					WithAPIKey(
						"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
						"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
					),
				},
			},
			wantErr: true,
		},
		{
			name: "error_zero_attachment_id",
			args: args{
				param: &ScansAttachmentPrepareParam{
					ScanID:       1,
					AttachmentID: 0,
				},
				request: &ScansAttachmentPrepareRequest{
					HistoryID: 123,
				},
				options: []Option{
					WithAPIURL("https://localhost:8834"),
					WithAPIKey(
						"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
						"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
					),
				},
			},
			wantErr: true,
		},
		{
			name: "error_empty_request",
			args: args{
				param: &ScansAttachmentPrepareParam{
					ScanID:       1,
					AttachmentID: 1,
				},
				request: nil,
				options: []Option{
					WithAPIURL("https://localhost:8834"),
					WithAPIKey(
						"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
						"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
					),
				},
			},
			wantErr: true,
		},
		{
			name: "success_with_token_auth",
			args: args{
				param: &ScansAttachmentPrepareParam{
					ScanID:       1,
					AttachmentID: 1,
				},
				request: &ScansAttachmentPrepareRequest{
					HistoryID: 123,
				},
				options: []Option{
					WithAPIURL("https://localhost:8834"),
					WithToken("62977d0ee34a809c6011d8afa0f037f5698f08c25829a74a"),
				},
			},
			wantErr: false,
		},
		{
			name: "error_with_invalid_token",
			args: args{
				param: &ScansAttachmentPrepareParam{
					ScanID:       1,
					AttachmentID: 1,
				},
				request: &ScansAttachmentPrepareRequest{
					HistoryID: 123,
				},
				options: []Option{
					WithAPIURL("https://localhost:8834"),
					WithToken("invalid-token"),
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(tt.args.options...)
			if err != nil && !tt.wantErr {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			got, err := c.ScansAttachmentPrepare(tt.args.param, tt.args.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScansAttachmentPrepare() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && got == nil {
				t.Errorf("ScansAttachmentPrepare() got = %v, want non-nil result", got)
			}
		})
	}
}
