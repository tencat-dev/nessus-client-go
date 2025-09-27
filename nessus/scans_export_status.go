package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type ScansExportStatusResponse struct {
	Status string `json:"status,omitempty"`
}

func (c *Client) ScansExportStatus(scanID string, fileID string) (*ScansExportStatusResponse, error) {
	resp, err := c.Get(c.getAPIURL("/scans/%d/export/%d/status", scanID, fileID))
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

	var data ScansExportStatusResponse
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return &data, nil
}
