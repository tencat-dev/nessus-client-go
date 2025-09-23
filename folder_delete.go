package nessus

import (
	"fmt"
	"io"
	"net/http"
)

func (c *Client) FolderDelete(id int) error {
	resp, err := c.Delete(c.apiURL+"/folder/"+fmt.Sprint(id), "application/json", nil)
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
