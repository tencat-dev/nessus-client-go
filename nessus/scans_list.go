package nessus

import (
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/bytedance/sonic"
)

type ScanResource struct {
	ID                   int    `json:"id,omitempty"`
	UUID                 string `json:"uuid,omitempty"`
	Name                 string `json:"name,omitempty"`
	Type                 string `json:"type,omitempty"`
	Owner                string `json:"owner,omitempty"`
	FolderID             int    `json:"folder_id,omitempty"`
	Read                 bool   `json:"read,omitempty"`
	Status               string `json:"status,omitempty"`
	Shared               bool   `json:"shared,omitempty"`
	UserPermissions      int    `json:"user_permissions,omitempty"`
	CreationDate         int    `json:"creation_date,omitempty"`
	LastModificationDate int    `json:"last_modification_date,omitempty"`
	Control              bool   `json:"control,omitempty"`
	Enabled              bool   `json:"enabled,omitempty"`
	Starttime            string `json:"starttime,omitempty"`
	Timezone             string `json:"timezone,omitempty"`
	Rrules               string `json:"rrules,omitempty"`
}

type ScansListQuery struct {
	FolderID             *int
	LastModificationDate *int
}

type ScansListResponse struct {
	Folders   []*FolderResource `json:"folders,omitempty"`
	Scans     []*ScanResource   `json:"scans,omitempty"`
	Timestamp int               `json:"timestamp,omitempty"`
}

func (c *Client) ScansList(query *ScansListQuery) (*ScansListResponse, error) {
	params := url.Values{}

	if query.FolderID != nil {
		params.Add("folder_id", fmt.Sprintf("%d", *query.FolderID))
	}

	if query.LastModificationDate != nil {
		params.Add("last_modification_date", fmt.Sprintf("%d", *query.LastModificationDate))
	}

	apiPath := "/scans"
	queryStr := params.Encode()

	if queryStr != "" {
		apiPath = fmt.Sprintf("%s?%s", apiPath, queryStr)
	}

	resp, err := c.Get(c.getAPIURL(apiPath))
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

	var data ScansListResponse

	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return &data, nil
}
