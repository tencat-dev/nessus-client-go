package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type FolderResource struct {
	ID          int    `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Type        string `json:"type,omitempty"`
	DefaultTag  int    `json:"default_tag,omitempty"`
	Custom      int    `json:"custom,omitempty"`
	UnreadCount int    `json:"unread_count,omitempty"`
}

type FoldersGetResponse struct {
	Folders []*FolderResource `json:"folders,omitempty"`
}

func (c *Client) FoldersGet() (*FoldersGetResponse, error) {
	resp, err := c.Get(c.getAPIURL("/folders"))
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
