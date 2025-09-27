package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type ScansConfigureSetting struct {
	Name         string                `json:"name,omitempty"`
	Description  string                `json:"description,omitempty"`
	PolicyID     int                   `json:"policy_id,omitempty"`
	FolderID     int                   `json:"folder_id,omitempty"`
	ScannerID    int                   `json:"scanner_id,omitempty"`
	Enabled      bool                  `json:"enabled,omitempty"`
	Launch       string                `json:"launch,omitempty"`
	Starttime    string                `json:"starttime,omitempty"`
	Rrules       string                `json:"rrules,omitempty"`
	Timezone     string                `json:"timezone,omitempty"`
	TargetGroups []string              `json:"target_groups,omitempty"`
	AgentGroups  []string              `json:"agent_groups,omitempty"`
	TextTargets  []string              `json:"text_targets,omitempty"`
	FileTargets  []string              `json:"file_targets,omitempty"`
	Emails       string                `json:"emails,omitempty"`
	Acls         []*PermissionResource `json:"acls,omitempty"`
}

type ScansConfigureRequest struct {
	UUID     string                 `json:"uuid,omitempty"`
	Settings *ScansConfigureSetting `json:"settings,omitempty"`
}

type ScansConfigureResponse struct {
	CreationDate           int    `json:"creation_date,omitempty"`
	CustomTargets          string `json:"custom_targets,omitempty"`
	DefaultPermissions     int    `json:"default_permissions,omitempty"`
	Description            string `json:"description,omitempty"`
	Emails                 string `json:"emails,omitempty"`
	ID                     int    `json:"id,omitempty"`
	LastModificationDate   int    `json:"last_modification_date,omitempty"`
	Name                   string `json:"name,omitempty"`
	NotificationFilters    string `json:"notification_filters,omitempty"`
	NotificationFilterType string `json:"notification_filter_type,omitempty"`
	Owner                  string `json:"owner,omitempty"`
	OwnerID                int    `json:"owner_id,omitempty"`
	PolicyID               int    `json:"policy_id,omitempty"`
	Rrules                 string `json:"rrules,omitempty"`
	Shared                 int    `json:"shared,omitempty"`
	Starttime              string `json:"starttime,omitempty"`
	TagID                  int    `json:"tag_id,omitempty"`
	Timezone               string `json:"timezone,omitempty"`
	Type                   string `json:"type,omitempty"`
	UserPermissions        int    `json:"user_permissions,omitempty"`
	UUID                   string `json:"uuid,omitempty"`
}

func (c *Client) ScansConfigure(scanID int, request *ScansConfigureRequest) (*ScansConfigureResponse, error) {
	req, err := sonic.Marshal(request)
	if err != nil {
		return nil, err
	}

	resp, err := c.Put(c.getAPIURL("/scans/%d", scanID), "application/json", req)
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

	var data ScansConfigureResponse
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return &data, nil
}
