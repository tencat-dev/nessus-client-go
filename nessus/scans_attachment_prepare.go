package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type ScansAttachmentPrepareParam struct {
	ScanID       int `json:"scan_id"`
	AttachmentID int `json:"attachment_id"`
}

type ScansAttachmentPrepareRequest struct {
	HistoryID int `json:"history_id"`
}

type ScansAttachmentPrepareResponse struct {
	Token string `json:"id"`
}

func (c *Client) ScansAttachmentPrepare(param *ScansAttachmentPrepareParam, request *ScansAttachmentPrepareRequest) (*ScansAttachmentPrepareResponse, error) {
	reqBody, err := sonic.Marshal(&ScansAttachmentPrepareRequest{
		HistoryID: request.HistoryID,
	})
	if err != nil {
		return nil, err
	}

	resp, err := c.Post(c.getAPIURL("/scans/%v/attachments/%v/prepare", param.ScanID, param.AttachmentID), "application/json", reqBody)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, ErrorResponse(body)
	}

	var data ScansAttachmentPrepareResponse
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return &data, nil
}
