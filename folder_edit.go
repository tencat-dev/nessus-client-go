package nessus

import (
	"fmt"
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type FolderEditRequest struct {
	Name string `json:"name"`
}

func (c *Client) FolderEdit(id int, name string) error {
	reqBody, err := sonic.Marshal(&FolderEditRequest{
		Name: name,
	})
	if err != nil {
		return err
	}

	resp, err := c.Put(c.apiURL+"/folders/"+fmt.Sprint(id), "application/json", reqBody)
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
