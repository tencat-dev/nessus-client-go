package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type ScansDeleteBulkRequest struct {
	IDs []int `json:"ids,omitempty"`
}

type ScansDeleteBulkResponse struct {
	Deleted []int `json:"deleted,omitempty"`
}

func (c *Client) ScansDeleteBulk(ids []int) (*ScansDeleteBulkResponse, error) {
	reqBody, err := sonic.Marshal(&ScansDeleteBulkRequest{
		IDs: ids,
	})
	if err != nil {
		return nil, err
	}

	resp, err := c.Delete(c.getAPIURL("/scans"), "application/json", reqBody)
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

	var data ScansDeleteBulkResponse
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return &data, nil
}
