package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type SessionKeysResponse struct {
	AccessKey string `json:"accessKey"`
	SecretKey string `json:"secretKey"`
}

func (c *Client) SessionKeys() (*SessionKeysResponse, error) {
	resp, err := c.Put(c.getAPIURL("/session/keys"), "application/json", nil)
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

	var data SessionKeysResponse

	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return &data, nil
}
