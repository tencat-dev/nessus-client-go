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

func (c *Client) SessionKeys() error {
	resp, err := c.Put(c.apiURL+"/session/keys", "application/json", nil)
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

	var data SessionKeysResponse

	if err = sonic.Unmarshal(body, &data); err != nil {
		return err
	}

	return nil
}
