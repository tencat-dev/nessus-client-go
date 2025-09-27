package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type ScansCopyRequest struct {
	FolderID int    `json:"folder_id,omitempty"`
	Name     string `json:"name,omitempty"`
}

func (c *Client) ScansCopy(scanID int, request *ScansCopyRequest) (*ScanResource, error) {
	reqBody, err := sonic.Marshal(request)
	if err != nil {
		return nil, err
	}

	resp, err := c.Post(c.getAPIURL("/scans/%d/copy", scanID), "application/json", reqBody)
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

	var data ScanResource
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return &data, nil
}
