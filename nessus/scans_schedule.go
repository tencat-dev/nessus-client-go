package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type ScansScheduleRequest struct {
	Enabled bool `json:"enabled,omitempty"`
}

type ScansScheduleResponse struct {
	Enabled   bool   `json:"enabled,omitempty"`
	Control   bool   `json:"control,omitempty"`
	Rrules    string `json:"rrules,omitempty"`
	Starttime string `json:"starttime,omitempty"`
	Timezone  string `json:"timezone,omitempty"`
}

func (c *Client) ScansSchedule(id int, request *ScansScheduleRequest) (*ScansScheduleResponse, error) {
	req, err := sonic.Marshal(request)
	if err != nil {
		return nil, err
	}

	resp, err := c.Put(c.getAPIURL("/scans/%d/status", id), "application/json", req)
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

	var data ScansScheduleResponse
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return &data, nil
}
