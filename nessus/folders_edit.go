package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type FoldersEditRequest struct {
	Name string `json:"name"`
}

func (c *Client) FoldersEdit(id int, name string) error {
	reqBody, err := sonic.Marshal(&FoldersEditRequest{
		Name: name,
	})
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
