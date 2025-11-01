package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type ScanMoveRequest struct {
	FolderID int `json:"folder_id,omitempty"`
}

func (c *Client) ScansMove(scanID int, request *ScanMoveRequest) error {
	reqBody, err := sonic.Marshal(request)
	if err != nil {
		return err
	}

	resp, err := c.Put(c.getAPIURL("/scans/%d/folder", scanID), "application/json", reqBody)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return ErrorResponse(body)
	}

	return nil
}
