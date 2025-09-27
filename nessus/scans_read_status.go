package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type ScansReadStatusRequest struct {
	Read bool
}

func (c *Client) ScansReadStatus(id int, request *ScansReadStatusRequest) error {
	req, err := sonic.Marshal(request)
	if err != nil {
		return err
	}

	resp, err := c.Put(c.getAPIURL("/scans/%d/status", id), "application/json", req)
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
