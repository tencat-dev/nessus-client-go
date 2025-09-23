package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type FolderCreateRequest struct {
	Name string `json:"name"`
}

type FolderCreateResponse struct {
	ID int `json:"id"`
}

func (c *Client) FolderCreate(name string) (*FolderCreateResponse, error) {
	reqBody, err := sonic.Marshal(&FolderCreateRequest{
		Name: name,
	})
	if err != nil {
		return nil, err
	}

	resp, err := c.Post(c.apiURL+"/folders", "application/json", reqBody)
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

	var data FolderCreateResponse
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return &data, nil
}
