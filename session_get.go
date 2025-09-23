package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type Resource struct {
	ID          string   `json:"id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Permissions int      `json:"permissions"`
	Lastlogin   int      `json:"lastlogin"`
	ContainerID int      `json:"container_id"`
	Groups      []string `json:"groups"`
}

type SessionGetResponse struct {
	Session Resource `json:"session"`
}

func (c *Client) SessionGet() (*SessionGetResponse, error) {
	resp, err := c.Get(c.apiURL + "/session")
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

	var data SessionGetResponse

	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return &data, nil
}
