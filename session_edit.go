package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type SessionEditRequest struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

func (c *Client) SessionEdit(name string, email string) error {
	reqBody, err := sonic.Marshal(&SessionEditRequest{
		Name:  name,
		Email: email,
	})
	if err != nil {
		return err
	}
	resp, err := c.Put(c.apiURL+"/session", "application/json", reqBody)
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
