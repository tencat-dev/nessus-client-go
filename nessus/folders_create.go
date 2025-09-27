package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type FoldersCreateRequest struct {
	Name string `json:"name,omitempty"`
}

type FoldersCreateResponse struct {
	ID int `json:"id,omitempty"`
}

func (c *Client) FoldersCreate(req *FoldersCreateRequest) (*FoldersCreateResponse, error) {
	reqBody, err := sonic.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := c.Post(c.getAPIURL("/folders"), "application/json", reqBody)
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

	var data FoldersCreateResponse
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return &data, nil
}
