package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type ServerPropertiesResponse struct {
	IdleTimeout                     string          `json:"idle_timeout,omitempty"`
	UsedIPCount                     int             `json:"used_ip_count,omitempty"`
	ServerBuild                     string          `json:"server_build,omitempty"`
	UsersCount                      int             `json:"users_count,omitempty"`
	Installers                      *Installers     `json:"installers,omitempty"`
	License                         *License        `json:"license,omitempty"`
	Update                          *Update         `json:"update,omitempty"`
	Capabilities                    *Capabilities   `json:"capabilities,omitempty"`
	Md5SumWizardTemplates           string          `json:"md5sum_wizard_templates,omitempty"`
	NessusUIVersion                 string          `json:"nessus_ui_version,omitempty"`
	ServerVersion                   string          `json:"server_version,omitempty"`
	PluginSet                       string          `json:"plugin_set,omitempty"`
	NessusType                      string          `json:"nessus_type,omitempty"`
	IsOffline                       bool            `json:"is_offline,omitempty"`
	JavaInstalled                   bool            `json:"java_installed,omitempty"`
	ScannerBackendBoottime          int             `json:"scanner_backend_boottime,omitempty"`
	ScannerBoottime                 int             `json:"scanner_boottime,omitempty"`
	Md5SumTenableLinks              string          `json:"md5sum_tenable_links,omitempty"`
	Notifications                   []any           `json:"notifications,omitempty"`
	Restarting                      bool            `json:"restarting,omitempty"`
	Platform                        string          `json:"platform,omitempty"`
	NessusUIBuild                   string          `json:"nessus_ui_build,omitempty"`
	GuidesDisabled                  bool            `json:"guidesDisabled,omitempty"`
	LoadedPluginSet                 string          `json:"loaded_plugin_set,omitempty"`
	RestartNeeded                   any             `json:"restart_needed,omitempty"`
	TemplateVersionUpgradeNecessary any             `json:"template_version_upgrade_necessary,omitempty"`
	LoginBanner                     any             `json:"login_banner,omitempty"`
	RestartPending                  *RestartPending `json:"restart_pending,omitempty"`
	DisableRssWidget                any             `json:"disable_rss_widget,omitempty"`
	FeedNotifications               []any           `json:"feed_notifications,omitempty"`
	Npv7                            int             `json:"npv7,omitempty"`
	FeedError                       int             `json:"feed_error,omitempty"`
	UITheme                         string          `json:"ui_theme,omitempty"`
	TenableLinks                    []*TenableLinks `json:"tenable_links,omitempty"`
	Features                        *Features       `json:"features,omitempty"`
	TemplateVersion                 string          `json:"template_version,omitempty"`
	ServerUUID                      string          `json:"server_uuid,omitempty"`
}
type Installers struct{}
type Features struct {
	Policies     bool `json:"policies,omitempty"`
	Report       bool `json:"report,omitempty"`
	RemoteLink   bool `json:"remote_link,omitempty"`
	Cluster      bool `json:"cluster,omitempty"`
	Users        bool `json:"users,omitempty"`
	Vpr          bool `json:"vpr,omitempty"`
	Offline      bool `json:"offline,omitempty"`
	PluginRules  bool `json:"plugin_rules,omitempty"`
	API          bool `json:"api,omitempty"`
	ScanAPI      bool `json:"scan_api,omitempty"`
	Folders      bool `json:"folders,omitempty"`
	LocalScanner bool `json:"local_scanner,omitempty"`
	Logs         bool `json:"logs,omitempty"`
	SMTP         bool `json:"smtp,omitempty"`
}
type License struct {
	Features       *Features `json:"features,omitempty"`
	Type           string    `json:"type,omitempty"`
	ExpirationDate int       `json:"expiration_date,omitempty"`
	Ips            int64     `json:"ips,omitempty"`
	Restricted     bool      `json:"restricted,omitempty"`
	Agents         int       `json:"agents,omitempty"`
	Mode           int       `json:"mode,omitempty"`
	Scanners       int       `json:"scanners,omitempty"`
	ScannersUsed   int       `json:"scanners_used,omitempty"`
	AgentsUsed     int       `json:"agents_used,omitempty"`
	Name           string    `json:"name,omitempty"`
}
type Update struct {
	Href       any `json:"href,omitempty"`
	NewVersion int `json:"new_version,omitempty"`
	Restart    int `json:"restart,omitempty"`
}
type Capabilities struct {
	ScanVulnerabilityGroups      bool `json:"scan_vulnerability_groups,omitempty"`
	ReportEmailConfig            bool `json:"report_email_config,omitempty"`
	ScanVulnerabilityGroupsMixed bool `json:"scan_vulnerability_groups_mixed,omitempty"`
}
type RestartPending struct {
	Reason any `json:"reason,omitempty"`
	Type   any `json:"type,omitempty"`
}
type TenableLinks struct {
	SelectedIcon string `json:"selected_icon,omitempty"`
	Title        string `json:"title,omitempty"`
	Icon         string `json:"icon,omitempty"`
	Link         string `json:"link,omitempty"`
}

func (c *Client) ServerProperties() (*ServerPropertiesResponse, error) {
	resp, err := c.Get(c.apiURL + "/server/properties")
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

	var data ServerPropertiesResponse
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return &data, nil
}
