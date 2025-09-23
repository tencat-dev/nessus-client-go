package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type SessionDestroyResponse struct {
	StatusCode  uint8
	Description string
}

func (c *Client) SessionDestroy() (*SessionDestroyResponse, error) {
	resp, err := c.Delete(c.apiURL+"/session", "application/json", nil)
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

	var data SessionDestroyResponse
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

