package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type SessionKeysRequest struct {
	AccessKey string `json:"accessKey"`
	SecretKey string `json:"secretKey"`
}

type SessionKeysResponse struct {
	AccessKey string `json:"accessKey"`
	SecretKey string `json:"secretKey"`
}

func (c *Client) SessionKeys(req *SessionKeysRequest) (*SessionKeysResponse, error) {
	reqBody, err := sonic.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := c.Put(c.getAPIURL("/session/keys"), "application/json", reqBody)
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
