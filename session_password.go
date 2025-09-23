package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type SessionPasswordRequest struct {
	Password        string `json:"password"`
	CurrentPassword string `json:"current_password"`
}

func (c *Client) SessionPassword(password string, currentPassword string) error {
	reqBody, err := sonic.Marshal(&SessionPasswordRequest{
		Password:        password,
		CurrentPassword: currentPassword,
	})
	if err != nil {
		return err
	}
	resp, err := c.Put(c.apiURL+"/session/chpasswd", "application/json", reqBody)
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
