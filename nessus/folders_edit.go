package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type FoldersEditRequest struct {
	Name string `json:"name,omitempty"`
}

func (c *Client) FoldersEdit(id int, req *FoldersEditRequest) error {
	reqBody, err := sonic.Marshal(req)
	if err != nil {
		return err
	}

	resp, err := c.Put(c.getAPIURL("/folders/%d", id), "application/json", reqBody)
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
