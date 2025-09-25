package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type ScansLaunchRequest struct {
	AltTargets []string `json:"alt_targets,omitempty"`
}

type ScansLaunchResponse struct {
	ScanUUID string `json:"scan_uuid,omitempty"`
}

func (c *Client) ScansLaunch(id int, request *ScansLaunchRequest) (*ScansLaunchResponse, error) {
	reqBody, err := sonic.Marshal(request)
	if err != nil {
		return nil, err
	}

	resp, err := c.Post(c.getAPIURL("/scans/%d/launch", &id), "application/json", reqBody)
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

	var data ScansLaunchResponse
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return &data, nil
}
