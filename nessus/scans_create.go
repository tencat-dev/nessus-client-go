package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type ScansCreateSetting struct {
	Name         string   `json:"name,omitempty"`
	Description  string   `json:"description,omitempty"`
	Emails       string   `json:"emails,omitempty"`
	Enabled      bool     `json:"enabled,omitempty"`
	Launch       string   `json:"launch,omitempty"`
	LaunchNow    string   `json:"launch_now,omitempty"`
	FolderID     string   `json:"folder_id,omitempty"`
	PolicyID     string   `json:"policy_id,omitempty"`
	ScannerID    string   `json:"scanner_id,omitempty"`
	TextTargets  string   `json:"text_targets,omitempty"`
	AgentGroupID []string `json:"agent_group_id,omitempty"`
}

type ScansCreateRequest struct {
	TemplateUUID string              `json:"uuid,omitempty"`
	Settings     *ScansCreateSetting `json:"settings,omitempty"`
}

type ScanResult struct {
	CreationDate           int    `json:"creation_date,omitempty"`
	CustomTargets          string `json:"custom_targets,omitempty"`
	DefaultPermissions     int    `json:"default_permissions,omitempty"`
	Description            string `json:"description,omitempty"`
	Emails                 string `json:"emails,omitempty"`
	ID                     int    `json:"id,omitempty"`
	LastModificationDate   int    `json:"last_modification_date,omitempty"`
	Name                   string `json:"name,omitempty"`
	NotificationFilterType string `json:"notification_filter_type,omitempty"`
	NotificationFilters    string `json:"notification_filters,omitempty"`
	Owner                  string `json:"owner,omitempty"`
	OwnerID                int    `json:"owner_id,omitempty"`
	PolicyID               int    `json:"policy_id,omitempty"`
	Enabled                int    `json:"enabled,omitempty"`
	Rrules                 string `json:"rrules,omitempty"`
	ScannerID              int    `json:"scanner_id,omitempty"`
	Shared                 int    `json:"shared,omitempty"`
	Starttime              string `json:"starttime,omitempty"`
	TagID                  int    `json:"tag_id,omitempty"`
	Timezone               string `json:"timezone,omitempty"`
	Type                   string `json:"type,omitempty"`
	UserPermissions        int    `json:"user_permissions,omitempty"`
	UUID                   string `json:"uuid,omitempty"`
}

type ScansCreateResponse struct {
	Scan *ScanResult `json:"scan,omitempty"`
}

func (c *Client) ScansCreate(request *ScansCreateRequest) (*ScansCreateResponse, error) {
	reqBody, err := sonic.Marshal(request)
	if err != nil {
		return nil, err
	}

	resp, err := c.Post(c.getAPIURL("/scans"), "application/json", reqBody)
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

	var data ScansCreateResponse
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return &data, nil
}
