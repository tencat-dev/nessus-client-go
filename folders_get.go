package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type FolderResource struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	DefaultTag  int    `json:"default_tag"`
	Custom      int    `json:"custom"`
	UnreadCount int    `json:"unread_count"`
}

type FoldersGetResponse struct {
	Folders []FolderResource `json:"folders"`
}

func (c *Client) FoldersGet() (*FoldersGetResponse, error) {
	resp, err := c.Get(c.apiURL + "/folders")
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

	var data FoldersGetResponse

	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return &data, nil
}
