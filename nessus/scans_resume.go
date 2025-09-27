package nessus

import (
	"io"
	"net/http"
)

func (c *Client) ScansResume(id int) error {
	resp, err := c.Post(c.getAPIURL("/scans/%d/resume", id), "application/json", nil)
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
