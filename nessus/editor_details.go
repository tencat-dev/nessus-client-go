package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type EditorDetailsResponse struct {
	Credentials struct {
		Data []struct {
			Types []struct {
				Inputs []struct {
					ID       string `json:"id,omitempty"`
					Name     string `json:"name,omitempty"`
					Type     string `json:"type,omitempty"`
					Hint     string `json:"hint,omitempty"`
					Required bool   `json:"required,omitempty"`
					Default  string `json:"default,omitempty"`
				} `json:"inputs,omitempty"`
				Max       int    `json:"max,omitempty"`
				Name      string `json:"name,omitempty"`
				Instances []any  `json:"instances,omitempty"`
				Settings  any    `json:"settings,omitempty"`
			} `json:"types,omitempty"`
			Name          string `json:"name,omitempty"`
			DefaultExpand int    `json:"default_expand,omitempty"`
		} `json:"data,omitempty"`
	} `json:"credentials,omitempty"`
	Compliance struct {
		Data []struct {
			Name     string `json:"name,omitempty"`
			Settings struct {
				Compliance struct {
					Inputs any    `json:"inputs,omitempty"`
					Title  string `json:"title,omitempty"`
					Groups []struct {
						Inputs   any    `json:"inputs,omitempty"`
						Title    string `json:"title,omitempty"`
						Name     string `json:"name,omitempty"`
						Sections []struct {
							Inputs []struct {
								Type string `json:"type,omitempty"`
								Name string `json:"name,omitempty"`
								ID   string `json:"id,omitempty"`
							} `json:"inputs,omitempty"`
							Desc  string `json:"desc,omitempty"`
							Title string `json:"title,omitempty"`
							Name  string `json:"name,omitempty"`
						} `json:"sections,omitempty"`
					} `json:"groups,omitempty"`
					Sections []any `json:"sections,omitempty"`
				} `json:"compliance,omitempty"`
			} `json:"settings,omitempty"`
			OfflineAllowed bool     `json:"offline_allowed,omitempty"`
			RequiredCreds  []string `json:"required_creds,omitempty"`
			Audits         []struct {
				Inputs []struct {
					ID       string `json:"id,omitempty"`
					Name     string `json:"name,omitempty"`
					Type     string `json:"type,omitempty"`
					Default  any    `json:"default,omitempty"`
					Required bool   `json:"required,omitempty"`
				} `json:"inputs,omitempty"`
				Type       string `json:"type,omitempty"`
				Name       string `json:"name,omitempty"`
				Free       int    `json:"free,omitempty"`
				Unlimited  bool   `json:"unlimited,omitempty"`
				ID         string `json:"id,omitempty"`
				Deprecated bool   `json:"deprecated,omitempty"`
			} `json:"audits,omitempty"`
		} `json:"data,omitempty"`
	} `json:"compliance,omitempty"`
	IsWas           bool   `json:"is_was,omitempty"`
	UserPermissions any    `json:"user_permissions,omitempty"`
	IsAgent         bool   `json:"is_agent,omitempty"`
	Owner           any    `json:"owner,omitempty"`
	Title           string `json:"title,omitempty"`
	UUID            string `json:"uuid,omitempty"`
	DynamicScan     bool   `json:"dynamic_scan,omitempty"`
	Plugins         struct {
		Families struct {
			SMTPProblems struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"SMTP problems,omitempty"`
			RockyLinuxLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Rocky Linux Local Security Checks,omitempty"`
			Backdoors struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Backdoors,omitempty"`
			RPC struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"RPC,omitempty"`
			GentooLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Gentoo Local Security Checks,omitempty"`
			OracleLinuxLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Oracle Linux Local Security Checks,omitempty"`
			ArtificialIntelligence struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Artificial Intelligence,omitempty"`
			BruteForceAttacks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Brute force attacks,omitempty"`
			GainAShellRemotely struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Gain a shell remotely,omitempty"`
			ServiceDetection struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Service detection,omitempty"`
			DNS struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"DNS,omitempty"`
			MandrivaLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Mandriva Local Security Checks,omitempty"`
			JunosLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Junos Local Security Checks,omitempty"`
			Misc struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Misc.,omitempty"`
			Ftp struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"FTP,omitempty"`
			SlackwareLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Slackware Local Security Checks,omitempty"`
			DefaultUnixAccounts struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Default Unix Accounts,omitempty"`
			AIXLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"AIX Local Security Checks,omitempty"`
			Snmp struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"SNMP,omitempty"`
			OracleVMLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"OracleVM Local Security Checks,omitempty"`
			CGIAbuses struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"CGI abuses,omitempty"`
			AzureLinuxLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Azure Linux Local Security Checks,omitempty"`
			Settings struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Settings,omitempty"`
			Cisco struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"CISCO,omitempty"`
			TencentLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Tencent Local Security Checks,omitempty"`
			TenableOt struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Tenable.ot,omitempty"`
			Firewalls struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Firewalls,omitempty"`
			Databases struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Databases,omitempty"`
			DebianLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Debian Local Security Checks,omitempty"`
			FedoraLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Fedora Local Security Checks,omitempty"`
			Netware struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Netware,omitempty"`
			HuaweiLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Huawei Local Security Checks,omitempty"`
			WindowsUserManagement struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Windows : User management,omitempty"`
			VirtuozzoLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Virtuozzo Local Security Checks,omitempty"`
			CentOSLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"CentOS Local Security Checks,omitempty"`
			PeerToPeerFileSharing struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Peer-To-Peer File Sharing,omitempty"`
			NewStartCGSLLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"NewStart CGSL Local Security Checks,omitempty"`
			MarinerOSLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"MarinerOS Local Security Checks,omitempty"`
			General struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"General,omitempty"`
			PolicyCompliance struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Policy Compliance,omitempty"`
			AmazonLinuxLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Amazon Linux Local Security Checks,omitempty"`
			SolarisLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Solaris Local Security Checks,omitempty"`
			F5NetworksLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"F5 Networks Local Security Checks,omitempty"`
			DenialOfService struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Denial of Service,omitempty"`
			WindowsMicrosoftBulletins struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Windows : Microsoft Bulletins,omitempty"`
			SuSELocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"SuSE Local Security Checks,omitempty"`
			PaloAltoLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Palo Alto Local Security Checks,omitempty"`
			TenableOtViolation struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Tenable.ot Violation,omitempty"`
			AlibabaCloudLinuxLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Alibaba Cloud Linux Local Security Checks,omitempty"`
			RedHatLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Red Hat Local Security Checks,omitempty"`
			PhotonOSLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"PhotonOS Local Security Checks,omitempty"`
			AlmaLinuxLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Alma Linux Local Security Checks,omitempty"`
			HPUXLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"HP-UX Local Security Checks,omitempty"`
			CGIAbusesXSS struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"CGI abuses : XSS,omitempty"`
			FreeBSDLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"FreeBSD Local Security Checks,omitempty"`
			Windows struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Windows,omitempty"`
			ScientificLinuxLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Scientific Linux Local Security Checks,omitempty"`
			MacOSXLocalSecurityChecks struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"MacOS X Local Security Checks,omitempty"`
			WebServers struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"Web Servers,omitempty"`
			Scada struct {
				Count  int    `json:"count,omitempty"`
				ID     int    `json:"id,omitempty"`
				Locked bool   `json:"locked,omitempty"`
				Status string `json:"status,omitempty"`
			} `json:"SCADA,omitempty"`
		} `json:"families,omitempty"`
	} `json:"plugins,omitempty"`
	FilterAttributes []any `json:"filter_attributes,omitempty"`
	Migrated         any   `json:"migrated,omitempty"`
	Settings         struct {
		Basic struct {
			Inputs []struct {
				Type     string `json:"type,omitempty"`
				Name     string `json:"name,omitempty"`
				ID       string `json:"id,omitempty"`
				Required bool   `json:"required,omitempty"`
				Options  []struct {
					Name string `json:"name,omitempty"`
					ID   int    `json:"id,omitempty"`
				} `json:"options,omitempty"`
				Placeholder string `json:"placeholder,omitempty"`
			} `json:"inputs,omitempty"`
			Title  string `json:"title,omitempty"`
			Groups []struct {
				Title  string `json:"title,omitempty"`
				Name   string `json:"name,omitempty"`
				Inputs []struct {
					Type        string `json:"type,omitempty"`
					Name        string `json:"name,omitempty"`
					Placeholder string `json:"placeholder,omitempty"`
				} `json:"inputs,omitempty"`
				Filters []any `json:"filters,omitempty"`
				Acls    any   `json:"acls,omitempty"`
			} `json:"groups,omitempty"`
			Sections []any `json:"sections,omitempty"`
		} `json:"basic,omitempty"`
		Advanced struct {
			Inputs any `json:"inputs,omitempty"`
			Modes  []struct {
				Desc        string `json:"desc,omitempty"`
				ID          string `json:"id,omitempty"`
				Name        string `json:"name,omitempty"`
				DescIo      string `json:"desc_io,omitempty"`
				Preferences struct {
					ChecksReadTimeout string `json:"checks_read_timeout,omitempty"`
					MaxChecks         string `json:"max_checks,omitempty"`
					MaxHosts          string `json:"max_hosts,omitempty"`
				} `json:"preferences,omitempty"`
				Default       bool `json:"default,omitempty"`
				PreferencesIo struct {
					HostTagging       string `json:"host_tagging,omitempty"`
					ChecksReadTimeout string `json:"checks_read_timeout,omitempty"`
					MaxChecks         string `json:"max_checks,omitempty"`
					MaxHosts          string `json:"max_hosts,omitempty"`
				} `json:"preferences_io,omitempty"`
				Preferences0 struct {
					ChecksReadTimeout             string `json:"checks_read_timeout,omitempty"`
					MaxChecks                     string `json:"max_checks,omitempty"`
					ReduceConnectionsOnCongestion string `json:"reduce_connections_on_congestion,omitempty"`
					MaxHosts                      string `json:"max_hosts,omitempty"`
				} `json:"preferences,omitempty"`
				Preferences1 struct {
					ChecksReadTimeout             string `json:"checks_read_timeout,omitempty"`
					MaxChecks                     string `json:"max_checks,omitempty"`
					ReduceConnectionsOnCongestion string `json:"reduce_connections_on_congestion,omitempty"`
					MaxHosts                      string `json:"max_hosts,omitempty"`
				} `json:"preferences,omitempty"`
				PreferencesIo0 struct {
					HostTagging                   string `json:"host_tagging,omitempty"`
					ChecksReadTimeout             string `json:"checks_read_timeout,omitempty"`
					MaxChecks                     string `json:"max_checks,omitempty"`
					ReduceConnectionsOnCongestion string `json:"reduce_connections_on_congestion,omitempty"`
					MaxHosts                      string `json:"max_hosts,omitempty"`
				} `json:"preferences_io,omitempty"`
				Custom bool `json:"custom,omitempty"`
			} `json:"modes,omitempty"`
			Title    string `json:"title,omitempty"`
			Groups   []any  `json:"groups,omitempty"`
			Sections []struct {
				Inputs []struct {
					Type                  string   `json:"type,omitempty"`
					ID                    string   `json:"id,omitempty"`
					Label                 string   `json:"label,omitempty"`
					Default               string   `json:"default,omitempty"`
					Hint                  string   `json:"hint,omitempty"`
					ExcludedTemplateUuids []string `json:"excluded_template_uuids,omitempty"`
					Name                  string   `json:"name,omitempty"`
					Placeholder           string   `json:"placeholder,omitempty"`
					NoSc                  bool     `json:"no_sc,omitempty"`
				} `json:"inputs,omitempty"`
				Title string `json:"title,omitempty"`
				Name  string `json:"name,omitempty"`
			} `json:"sections,omitempty"`
		} `json:"advanced,omitempty"`
		Assessment struct {
			Inputs any `json:"inputs,omitempty"`
			Modes  []struct {
				Desc        string `json:"desc,omitempty"`
				ID          string `json:"id,omitempty"`
				Name        string `json:"name,omitempty"`
				Preferences struct {
					GlobalVariableSettingsRadioReportParanoia                                       string `json:"Global variable settings[radio]:Report paranoia,omitempty"`
					GlobalVariableSettingsCheckboxDoNotLogInWithUserAccountsNotSpecifiedInThePolicy string `json:"Global variable settings[checkbox]:Do not log in with user accounts not specified in the policy,omitempty"`
					GlobalVariableSettingsCheckboxEnableCGIScanning                                 string `json:"Global variable settings[checkbox]:Enable CGI scanning,omitempty"`
					GlobalVariableSettingsCheckboxThoroughTestsSlow                                 string `json:"Global variable settings[checkbox]:Thorough tests (slow),omitempty"`
				} `json:"preferences,omitempty"`
				Preferences0 struct {
					GlobalVariableSettingsRadioReportParanoia       string `json:"Global variable settings[radio]:Report paranoia,omitempty"`
					GlobalVariableSettingsCheckboxThoroughTestsSlow string `json:"Global variable settings[checkbox]:Thorough tests (slow),omitempty"`
				} `json:"preferences,omitempty"`
				Preferences1 struct {
					WebApplicationTestsSettingsCheckboxEnableWebApplicationsTests                                      string `json:"Web Application Tests Settings[checkbox]:Enable web applications tests,omitempty"`
					WebMirroringEntryMaximumDepth                                                                      string `json:"Web mirroring[entry]:Maximum depth :,omitempty"`
					GlobalVariableSettingsRadioReportParanoia                                                          string `json:"Global variable settings[radio]:Report paranoia,omitempty"`
					WebMirroringEntryExcludedItemsRegex                                                                string `json:"Web mirroring[entry]:Excluded items regex :,omitempty"`
					WebMirroringEntryNumberOfPagesToMirror                                                             string `json:"Web mirroring[entry]:Number of pages to mirror :,omitempty"`
					GlobalVariableSettingsEntryHTTPUserAgent                                                           string `json:"Global variable settings[entry]:HTTP User-Agent,omitempty"`
					WebMirroringCheckboxFollowDynamicPages                                                             string `json:"Web mirroring[checkbox]:Follow dynamic pages :,omitempty"`
					GlobalVariableSettingsCheckboxEnableCGIScanning                                                    string `json:"Global variable settings[checkbox]:Enable CGI scanning,omitempty"`
					GlobalVariableSettingsCheckboxThoroughTestsSlow                                                    string `json:"Global variable settings[checkbox]:Thorough tests (slow),omitempty"`
					RemoteWebServerScreenshotCheckboxAllowNessusToConnectToTheCloudToTakeAScreenshotOfThePublicTargets string `json:"Remote web server screenshot[checkbox]:Allow Nessus to connect to the cloud to take a screenshot of the public targets,omitempty"`
					WebMirroringEntryStartPage                                                                         string `json:"Web mirroring[entry]:Start page :,omitempty"`
				} `json:"preferences,omitempty"`
				Preferences2 struct {
					WebApplicationTestsSettingsRadioStopAtFirstFlaw                                                    string `json:"Web Application Tests Settings[radio]:Stop at first flaw,omitempty"`
					WebApplicationTestsSettingsCheckboxEnableWebApplicationsTests                                      string `json:"Web Application Tests Settings[checkbox]:Enable web applications tests,omitempty"`
					WebMirroringEntryMaximumDepth                                                                      string `json:"Web mirroring[entry]:Maximum depth :,omitempty"`
					GlobalVariableSettingsRadioReportParanoia                                                          string `json:"Global variable settings[radio]:Report paranoia,omitempty"`
					WebMirroringEntryExcludedItemsRegex                                                                string `json:"Web mirroring[entry]:Excluded items regex :,omitempty"`
					HTTPLoginPageCheckboxAbortWebApplicationTestsIfLoginFails                                          string `json:"HTTP login page[checkbox]:Abort web application tests if login fails,omitempty"`
					WebApplicationTestsSettingsCheckboxHTTPParameterPollution                                          string `json:"Web Application Tests Settings[checkbox]:HTTP Parameter Pollution,omitempty"`
					WebMirroringEntryNumberOfPagesToMirror                                                             string `json:"Web mirroring[entry]:Number of pages to mirror :,omitempty"`
					GlobalVariableSettingsEntryHTTPUserAgent                                                           string `json:"Global variable settings[entry]:HTTP User-Agent,omitempty"`
					WebMirroringCheckboxFollowDynamicPages                                                             string `json:"Web mirroring[checkbox]:Follow dynamic pages :,omitempty"`
					GlobalVariableSettingsCheckboxEnableCGIScanning                                                    string `json:"Global variable settings[checkbox]:Enable CGI scanning,omitempty"`
					WebApplicationTestsSettingsEntryMaximumRunTimeMin                                                  string `json:"Web Application Tests Settings[entry]:Maximum run time (min) :,omitempty"`
					GlobalVariableSettingsCheckboxThoroughTestsSlow                                                    string `json:"Global variable settings[checkbox]:Thorough tests (slow),omitempty"`
					RemoteWebServerScreenshotCheckboxAllowNessusToConnectToTheCloudToTakeAScreenshotOfThePublicTargets string `json:"Remote web server screenshot[checkbox]:Allow Nessus to connect to the cloud to take a screenshot of the public targets,omitempty"`
					WebMirroringEntryStartPage                                                                         string `json:"Web mirroring[entry]:Start page :,omitempty"`
					WebApplicationTestsSettingsRadioCombinationsOfArgumentsValues                                      string `json:"Web Application Tests Settings[radio]:Combinations of arguments values,omitempty"`
					WebApplicationTestsSettingsCheckboxTestEmbeddedWebServers                                          string `json:"Web Application Tests Settings[checkbox]:Test embedded web servers,omitempty"`
					WebApplicationTestsSettingsEntryURLForRemoteFileInclusion                                          string `json:"Web Application Tests Settings[entry]:URL for Remote File Inclusion :,omitempty"`
					WebApplicationTestsSettingsCheckboxTryAllHTTPMethods                                               string `json:"Web Application Tests Settings[checkbox]:Try all HTTP methods,omitempty"`
				} `json:"preferences,omitempty"`
				Default      bool `json:"default,omitempty"`
				Preferences3 struct {
					WebApplicationTestsSettingsRadioStopAtFirstFlaw                                                    string `json:"Web Application Tests Settings[radio]:Stop at first flaw,omitempty"`
					WebApplicationTestsSettingsCheckboxEnableWebApplicationsTests                                      string `json:"Web Application Tests Settings[checkbox]:Enable web applications tests,omitempty"`
					WebMirroringEntryMaximumDepth                                                                      string `json:"Web mirroring[entry]:Maximum depth :,omitempty"`
					GlobalVariableSettingsRadioReportParanoia                                                          string `json:"Global variable settings[radio]:Report paranoia,omitempty"`
					WebMirroringEntryExcludedItemsRegex                                                                string `json:"Web mirroring[entry]:Excluded items regex :,omitempty"`
					HTTPLoginPageCheckboxAbortWebApplicationTestsIfLoginFails                                          string `json:"HTTP login page[checkbox]:Abort web application tests if login fails,omitempty"`
					WebApplicationTestsSettingsCheckboxHTTPParameterPollution                                          string `json:"Web Application Tests Settings[checkbox]:HTTP Parameter Pollution,omitempty"`
					WebMirroringEntryNumberOfPagesToMirror                                                             string `json:"Web mirroring[entry]:Number of pages to mirror :,omitempty"`
					GlobalVariableSettingsEntryHTTPUserAgent                                                           string `json:"Global variable settings[entry]:HTTP User-Agent,omitempty"`
					WebMirroringCheckboxFollowDynamicPages                                                             string `json:"Web mirroring[checkbox]:Follow dynamic pages :,omitempty"`
					GlobalVariableSettingsCheckboxEnableCGIScanning                                                    string `json:"Global variable settings[checkbox]:Enable CGI scanning,omitempty"`
					WebApplicationTestsSettingsEntryMaximumRunTimeMin                                                  string `json:"Web Application Tests Settings[entry]:Maximum run time (min) :,omitempty"`
					GlobalVariableSettingsCheckboxThoroughTestsSlow                                                    string `json:"Global variable settings[checkbox]:Thorough tests (slow),omitempty"`
					RemoteWebServerScreenshotCheckboxAllowNessusToConnectToTheCloudToTakeAScreenshotOfThePublicTargets string `json:"Remote web server screenshot[checkbox]:Allow Nessus to connect to the cloud to take a screenshot of the public targets,omitempty"`
					WebMirroringEntryStartPage                                                                         string `json:"Web mirroring[entry]:Start page :,omitempty"`
					WebApplicationTestsSettingsRadioCombinationsOfArgumentsValues                                      string `json:"Web Application Tests Settings[radio]:Combinations of arguments values,omitempty"`
					WebApplicationTestsSettingsCheckboxTestEmbeddedWebServers                                          string `json:"Web Application Tests Settings[checkbox]:Test embedded web servers,omitempty"`
					WebApplicationTestsSettingsEntryURLForRemoteFileInclusion                                          string `json:"Web Application Tests Settings[entry]:URL for Remote File Inclusion :,omitempty"`
					WebApplicationTestsSettingsCheckboxTryAllHTTPMethods                                               string `json:"Web Application Tests Settings[checkbox]:Try all HTTP methods,omitempty"`
				} `json:"preferences,omitempty"`
				Custom string `json:"custom,omitempty"`
			} `json:"modes,omitempty"`
			Title  string `json:"title,omitempty"`
			Groups []struct {
				Inputs   any    `json:"inputs,omitempty"`
				Title    string `json:"title,omitempty"`
				Name     string `json:"name,omitempty"`
				Sections []struct {
					Inputs []struct {
						Type          string   `json:"type,omitempty"`
						ID            string   `json:"id,omitempty"`
						Label         string   `json:"label,omitempty"`
						Default       string   `json:"default,omitempty"`
						Options       []string `json:"options,omitempty"`
						OptionsLabels []string `json:"optionsLabels,omitempty"`
						Hint          string   `json:"hint,omitempty"`
					} `json:"inputs,omitempty"`
					Title string `json:"title,omitempty"`
					Name  string `json:"name,omitempty"`
				} `json:"sections,omitempty"`
				NoHome bool `json:"no_home,omitempty"`
			} `json:"groups,omitempty"`
			Sections []any `json:"sections,omitempty"`
		} `json:"assessment,omitempty"`
		Discovery struct {
			Inputs any `json:"inputs,omitempty"`
			Modes  []struct {
				Desc        string `json:"desc,omitempty"`
				ID          string `json:"id,omitempty"`
				Name        string `json:"name,omitempty"`
				Default     bool   `json:"default,omitempty"`
				Preferences struct {
					PingTheRemoteHostCheckboxDoAnARPPing                                               string `json:"Ping the remote host[checkbox]:Do an ARP ping,omitempty"`
					PingTheRemoteHostEntryNumberOfRetriesICMP                                          string `json:"Ping the remote host[entry]:Number of retries (ICMP) :,omitempty"`
					PortScannersSettingsCheckboxOnlyRunNetworkPortScannersIfLocalPortEnumerationFailed string `json:"Port scanners settings[checkbox]:Only run network port scanners if local port enumeration failed,omitempty"`
					PluginSelectionIndividualPlugin14274                                               string `json:"plugin_selection.individual_plugin.14274,omitempty"`
					PingTheRemoteHostCheckboxTestTheLocalNessusHost                                    string `json:"Ping the remote host[checkbox]:Test the local Nessus host,omitempty"`
					NetworkScannersUDP                                                                 string `json:"network_scanners.udp,omitempty"`
					PortRange                                                                          string `json:"port_range,omitempty"`
					PingTheRemoteHostCheckboxDoAnApplicativeUDPPingDNSRPC                              string `json:"Ping the remote host[checkbox]:Do an applicative UDP ping (DNS,RPC...),omitempty"`
					NetworkScannersSyn                                                                 string `json:"network_scanners.syn,omitempty"`
					PingTheRemoteHostCheckboxDoAnICMPPing                                              string `json:"Ping the remote host[checkbox]:Do an ICMP ping,omitempty"`
					PluginSelectionIndividualPlugin11219                                               string `json:"plugin_selection.individual_plugin.11219,omitempty"`
					WakeOnLANEntryTimeToWaitInMinutesForTheSystemsToBoot                               string `json:"Wake-on-LAN[entry]:Time to wait (in minutes) for the systems to boot:,omitempty"`
					NessusSYNScannerRadioFirewallDetection                                             string `json:"Nessus SYN scanner[radio]:Firewall detection :,omitempty"`
					PortscanPing                                                                       string `json:"portscan.ping,omitempty"`
					GlobalVariableSettingsRadioNetworkType                                             string `json:"Global variable settings[radio]:Network type,omitempty"`
					UnscannedClosed                                                                    string `json:"unscanned_closed,omitempty"`
					NetworkScannersTCP                                                                 string `json:"network_scanners.tcp,omitempty"`
					PingTheRemoteHostCheckboxInterpretICMPUnreachFromGateway                           string `json:"Ping the remote host[checkbox]:Interpret ICMP unreach from gateway,omitempty"`
					WakeOnLANFileListOfMACAddressesForWakeOnLAN                                        string `json:"Wake-on-LAN[file]:List of MAC addresses for Wake-on-LAN:,omitempty"`
					TestSSLBasedServices                                                               string `json:"Test SSL based services,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNovellNetwareHosts                              string `json:"Do not scan fragile devices[checkbox]:Scan Novell Netware hosts,omitempty"`
					PluginSelectionIndividualPlugin34220                                               string `json:"plugin_selection.individual_plugin.34220,omitempty"`
					LocalPortscanSnmp                                                                  string `json:"local_portscan.snmp,omitempty"`
					PluginSelectionIndividualPlugin10180                                               string `json:"plugin_selection.individual_plugin.10180,omitempty"`
					PingTheRemoteHostCheckboxFastNetworkDiscovery                                      string `json:"Ping the remote host[checkbox]:Fast network discovery,omitempty"`
					PingTheRemoteHostEntryTCPPingDestinationPortS                                      string `json:"Ping the remote host[entry]:TCP ping destination port(s) :,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNetworkPrinters                                 string `json:"Do not scan fragile devices[checkbox]:Scan Network Printers,omitempty"`
					GlobalVariableSettingsCheckboxThoroughTestsSlow                                    string `json:"Global variable settings[checkbox]:Thorough tests (slow),omitempty"`
					PluginSelectionIndividualPlugin14272                                               string `json:"plugin_selection.individual_plugin.14272,omitempty"`
					LocalPortscanNetstatWmi                                                            string `json:"local_portscan.netstat_wmi,omitempty"`
					NessusTCPScannerRadioFirewallDetection                                             string `json:"Nessus TCP scanner[radio]:Firewall detection :,omitempty"`
					LocalPortscanNetstatSSH                                                            string `json:"local_portscan.netstat_ssh,omitempty"`
					PortScannersSettingsCheckboxCheckOpenTCPPortsFoundByLocalPortEnumerators           string `json:"Port scanners settings[checkbox]:Check open TCP ports found by local port enumerators,omitempty"`
					PingTheRemoteHostCheckboxDoATCPPing                                                string `json:"Ping the remote host[checkbox]:Do a TCP ping,omitempty"`
				} `json:"preferences,omitempty"`
				Preferences0 struct {
					PingTheRemoteHostCheckboxDoAnARPPing                                               string `json:"Ping the remote host[checkbox]:Do an ARP ping,omitempty"`
					PingTheRemoteHostEntryNumberOfRetriesICMP                                          string `json:"Ping the remote host[entry]:Number of retries (ICMP) :,omitempty"`
					PortScannersSettingsCheckboxOnlyRunNetworkPortScannersIfLocalPortEnumerationFailed string `json:"Port scanners settings[checkbox]:Only run network port scanners if local port enumeration failed,omitempty"`
					PluginSelectionIndividualPlugin14274                                               string `json:"plugin_selection.individual_plugin.14274,omitempty"`
					PingTheRemoteHostCheckboxTestTheLocalNessusHost                                    string `json:"Ping the remote host[checkbox]:Test the local Nessus host,omitempty"`
					NetworkScannersUDP                                                                 string `json:"network_scanners.udp,omitempty"`
					PortRange                                                                          string `json:"port_range,omitempty"`
					PingTheRemoteHostCheckboxDoAnApplicativeUDPPingDNSRPC                              string `json:"Ping the remote host[checkbox]:Do an applicative UDP ping (DNS,RPC...),omitempty"`
					NetworkScannersSyn                                                                 string `json:"network_scanners.syn,omitempty"`
					PingTheRemoteHostCheckboxDoAnICMPPing                                              string `json:"Ping the remote host[checkbox]:Do an ICMP ping,omitempty"`
					PluginSelectionIndividualPlugin11219                                               string `json:"plugin_selection.individual_plugin.11219,omitempty"`
					WakeOnLANEntryTimeToWaitInMinutesForTheSystemsToBoot                               string `json:"Wake-on-LAN[entry]:Time to wait (in minutes) for the systems to boot:,omitempty"`
					NessusSYNScannerRadioFirewallDetection                                             string `json:"Nessus SYN scanner[radio]:Firewall detection :,omitempty"`
					PortscanPing                                                                       string `json:"portscan.ping,omitempty"`
					GlobalVariableSettingsRadioNetworkType                                             string `json:"Global variable settings[radio]:Network type,omitempty"`
					UnscannedClosed                                                                    string `json:"unscanned_closed,omitempty"`
					NetworkScannersTCP                                                                 string `json:"network_scanners.tcp,omitempty"`
					PingTheRemoteHostCheckboxInterpretICMPUnreachFromGateway                           string `json:"Ping the remote host[checkbox]:Interpret ICMP unreach from gateway,omitempty"`
					WakeOnLANFileListOfMACAddressesForWakeOnLAN                                        string `json:"Wake-on-LAN[file]:List of MAC addresses for Wake-on-LAN:,omitempty"`
					TestSSLBasedServices                                                               string `json:"Test SSL based services,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNovellNetwareHosts                              string `json:"Do not scan fragile devices[checkbox]:Scan Novell Netware hosts,omitempty"`
					PluginSelectionIndividualPlugin34220                                               string `json:"plugin_selection.individual_plugin.34220,omitempty"`
					LocalPortscanSnmp                                                                  string `json:"local_portscan.snmp,omitempty"`
					PluginSelectionIndividualPlugin10180                                               string `json:"plugin_selection.individual_plugin.10180,omitempty"`
					PingTheRemoteHostCheckboxFastNetworkDiscovery                                      string `json:"Ping the remote host[checkbox]:Fast network discovery,omitempty"`
					PingTheRemoteHostEntryTCPPingDestinationPortS                                      string `json:"Ping the remote host[entry]:TCP ping destination port(s) :,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNetworkPrinters                                 string `json:"Do not scan fragile devices[checkbox]:Scan Network Printers,omitempty"`
					PluginSelectionIndividualPlugin14272                                               string `json:"plugin_selection.individual_plugin.14272,omitempty"`
					LocalPortscanNetstatWmi                                                            string `json:"local_portscan.netstat_wmi,omitempty"`
					NessusTCPScannerRadioFirewallDetection                                             string `json:"Nessus TCP scanner[radio]:Firewall detection :,omitempty"`
					LocalPortscanNetstatSSH                                                            string `json:"local_portscan.netstat_ssh,omitempty"`
					PortScannersSettingsCheckboxCheckOpenTCPPortsFoundByLocalPortEnumerators           string `json:"Port scanners settings[checkbox]:Check open TCP ports found by local port enumerators,omitempty"`
					PingTheRemoteHostCheckboxDoATCPPing                                                string `json:"Ping the remote host[checkbox]:Do a TCP ping,omitempty"`
				} `json:"preferences,omitempty"`
				Preferences1 struct {
					PluginSelectionIndividualPlugin34220                                               string `json:"plugin_selection.individual_plugin.34220,omitempty"`
					WakeOnLANFileListOfMACAddressesForWakeOnLAN                                        string `json:"Wake-on-LAN[file]:List of MAC addresses for Wake-on-LAN:,omitempty"`
					PingTheRemoteHostCheckboxDoAnICMPPing                                              string `json:"Ping the remote host[checkbox]:Do an ICMP ping,omitempty"`
					PluginSelectionIndividualPlugin14274                                               string `json:"plugin_selection.individual_plugin.14274,omitempty"`
					PortscanPing                                                                       string `json:"portscan.ping,omitempty"`
					PortScannersSettingsCheckboxOnlyRunNetworkPortScannersIfLocalPortEnumerationFailed string `json:"Port scanners settings[checkbox]:Only run network port scanners if local port enumeration failed,omitempty"`
					PingTheRemoteHostCheckboxDoAnARPPing                                               string `json:"Ping the remote host[checkbox]:Do an ARP ping,omitempty"`
					PingTheRemoteHostCheckboxDoAnApplicativeUDPPingDNSRPC                              string `json:"Ping the remote host[checkbox]:Do an applicative UDP ping (DNS,RPC...),omitempty"`
					LocalPortscanNetstatSSH                                                            string `json:"local_portscan.netstat_ssh,omitempty"`
					PluginSelectionIndividualPlugin10180                                               string `json:"plugin_selection.individual_plugin.10180,omitempty"`
					NetworkScannersTCP                                                                 string `json:"network_scanners.tcp,omitempty"`
					LocalPortscanSnmp                                                                  string `json:"local_portscan.snmp,omitempty"`
					PortRange                                                                          string `json:"port_range,omitempty"`
					NessusSYNScannerRadioFirewallDetection                                             string `json:"Nessus SYN scanner[radio]:Firewall detection :,omitempty"`
					PingTheRemoteHostEntryNumberOfRetriesICMP                                          string `json:"Ping the remote host[entry]:Number of retries (ICMP) :,omitempty"`
					PingTheRemoteHostEntryTCPPingDestinationPortS                                      string `json:"Ping the remote host[entry]:TCP ping destination port(s) :,omitempty"`
					PortScannersSettingsCheckboxCheckOpenTCPPortsFoundByLocalPortEnumerators           string `json:"Port scanners settings[checkbox]:Check open TCP ports found by local port enumerators,omitempty"`
					LocalPortscanNetstatWmi                                                            string `json:"local_portscan.netstat_wmi,omitempty"`
					PingTheRemoteHostCheckboxInterpretICMPUnreachFromGateway                           string `json:"Ping the remote host[checkbox]:Interpret ICMP unreach from gateway,omitempty"`
					NetworkScannersUDP                                                                 string `json:"network_scanners.udp,omitempty"`
					PingTheRemoteHostCheckboxDoATCPPing                                                string `json:"Ping the remote host[checkbox]:Do a TCP ping,omitempty"`
					NetworkScannersSyn                                                                 string `json:"network_scanners.syn,omitempty"`
					NessusTCPScannerRadioFirewallDetection                                             string `json:"Nessus TCP scanner[radio]:Firewall detection :,omitempty"`
					PluginSelectionIndividualPlugin11219                                               string `json:"plugin_selection.individual_plugin.11219,omitempty"`
					PluginSelectionIndividualPlugin14272                                               string `json:"plugin_selection.individual_plugin.14272,omitempty"`
					WakeOnLANEntryTimeToWaitInMinutesForTheSystemsToBoot                               string `json:"Wake-on-LAN[entry]:Time to wait (in minutes) for the systems to boot:,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNovellNetwareHosts                              string `json:"Do not scan fragile devices[checkbox]:Scan Novell Netware hosts,omitempty"`
					PingTheRemoteHostCheckboxTestTheLocalNessusHost                                    string `json:"Ping the remote host[checkbox]:Test the local Nessus host,omitempty"`
					UnscannedClosed                                                                    string `json:"unscanned_closed,omitempty"`
					GlobalVariableSettingsRadioNetworkType                                             string `json:"Global variable settings[radio]:Network type,omitempty"`
					PingTheRemoteHostCheckboxFastNetworkDiscovery                                      string `json:"Ping the remote host[checkbox]:Fast network discovery,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNetworkPrinters                                 string `json:"Do not scan fragile devices[checkbox]:Scan Network Printers,omitempty"`
				} `json:"preferences,omitempty"`
				Preferences2 struct {
					PluginSelectionIndividualPlugin34220                                               string `json:"plugin_selection.individual_plugin.34220,omitempty"`
					WakeOnLANFileListOfMACAddressesForWakeOnLAN                                        string `json:"Wake-on-LAN[file]:List of MAC addresses for Wake-on-LAN:,omitempty"`
					PingTheRemoteHostCheckboxDoAnICMPPing                                              string `json:"Ping the remote host[checkbox]:Do an ICMP ping,omitempty"`
					PluginSelectionIndividualPlugin14274                                               string `json:"plugin_selection.individual_plugin.14274,omitempty"`
					PortscanPing                                                                       string `json:"portscan.ping,omitempty"`
					PortScannersSettingsCheckboxOnlyRunNetworkPortScannersIfLocalPortEnumerationFailed string `json:"Port scanners settings[checkbox]:Only run network port scanners if local port enumeration failed,omitempty"`
					PingTheRemoteHostCheckboxDoAnARPPing                                               string `json:"Ping the remote host[checkbox]:Do an ARP ping,omitempty"`
					PingTheRemoteHostCheckboxDoAnApplicativeUDPPingDNSRPC                              string `json:"Ping the remote host[checkbox]:Do an applicative UDP ping (DNS,RPC...),omitempty"`
					LocalPortscanNetstatSSH                                                            string `json:"local_portscan.netstat_ssh,omitempty"`
					PluginSelectionIndividualPlugin10180                                               string `json:"plugin_selection.individual_plugin.10180,omitempty"`
					NetworkScannersTCP                                                                 string `json:"network_scanners.tcp,omitempty"`
					LocalPortscanSnmp                                                                  string `json:"local_portscan.snmp,omitempty"`
					PortRange                                                                          string `json:"port_range,omitempty"`
					NessusSYNScannerRadioFirewallDetection                                             string `json:"Nessus SYN scanner[radio]:Firewall detection :,omitempty"`
					PingTheRemoteHostEntryNumberOfRetriesICMP                                          string `json:"Ping the remote host[entry]:Number of retries (ICMP) :,omitempty"`
					PingTheRemoteHostEntryTCPPingDestinationPortS                                      string `json:"Ping the remote host[entry]:TCP ping destination port(s) :,omitempty"`
					PortScannersSettingsCheckboxCheckOpenTCPPortsFoundByLocalPortEnumerators           string `json:"Port scanners settings[checkbox]:Check open TCP ports found by local port enumerators,omitempty"`
					LocalPortscanNetstatWmi                                                            string `json:"local_portscan.netstat_wmi,omitempty"`
					PingTheRemoteHostCheckboxInterpretICMPUnreachFromGateway                           string `json:"Ping the remote host[checkbox]:Interpret ICMP unreach from gateway,omitempty"`
					NetworkScannersUDP                                                                 string `json:"network_scanners.udp,omitempty"`
					PingTheRemoteHostCheckboxDoATCPPing                                                string `json:"Ping the remote host[checkbox]:Do a TCP ping,omitempty"`
					NetworkScannersSyn                                                                 string `json:"network_scanners.syn,omitempty"`
					NessusTCPScannerRadioFirewallDetection                                             string `json:"Nessus TCP scanner[radio]:Firewall detection :,omitempty"`
					PluginSelectionIndividualPlugin11219                                               string `json:"plugin_selection.individual_plugin.11219,omitempty"`
					PluginSelectionIndividualPlugin14272                                               string `json:"plugin_selection.individual_plugin.14272,omitempty"`
					WakeOnLANEntryTimeToWaitInMinutesForTheSystemsToBoot                               string `json:"Wake-on-LAN[entry]:Time to wait (in minutes) for the systems to boot:,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNovellNetwareHosts                              string `json:"Do not scan fragile devices[checkbox]:Scan Novell Netware hosts,omitempty"`
					PingTheRemoteHostCheckboxTestTheLocalNessusHost                                    string `json:"Ping the remote host[checkbox]:Test the local Nessus host,omitempty"`
					UnscannedClosed                                                                    string `json:"unscanned_closed,omitempty"`
					GlobalVariableSettingsRadioNetworkType                                             string `json:"Global variable settings[radio]:Network type,omitempty"`
					PingTheRemoteHostCheckboxFastNetworkDiscovery                                      string `json:"Ping the remote host[checkbox]:Fast network discovery,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNetworkPrinters                                 string `json:"Do not scan fragile devices[checkbox]:Scan Network Printers,omitempty"`
				} `json:"preferences,omitempty"`
				Preferences3 struct {
					PluginSelectionIndividualPlugin34220                                               string `json:"plugin_selection.individual_plugin.34220,omitempty"`
					WakeOnLANFileListOfMACAddressesForWakeOnLAN                                        string `json:"Wake-on-LAN[file]:List of MAC addresses for Wake-on-LAN:,omitempty"`
					PingTheRemoteHostCheckboxDoAnICMPPing                                              string `json:"Ping the remote host[checkbox]:Do an ICMP ping,omitempty"`
					PluginSelectionIndividualPlugin14274                                               string `json:"plugin_selection.individual_plugin.14274,omitempty"`
					PortscanPing                                                                       string `json:"portscan.ping,omitempty"`
					PortScannersSettingsCheckboxOnlyRunNetworkPortScannersIfLocalPortEnumerationFailed string `json:"Port scanners settings[checkbox]:Only run network port scanners if local port enumeration failed,omitempty"`
					PingTheRemoteHostCheckboxDoAnARPPing                                               string `json:"Ping the remote host[checkbox]:Do an ARP ping,omitempty"`
					PingTheRemoteHostCheckboxDoAnApplicativeUDPPingDNSRPC                              string `json:"Ping the remote host[checkbox]:Do an applicative UDP ping (DNS,RPC...),omitempty"`
					LocalPortscanNetstatSSH                                                            string `json:"local_portscan.netstat_ssh,omitempty"`
					PluginSelectionIndividualPlugin10180                                               string `json:"plugin_selection.individual_plugin.10180,omitempty"`
					NetworkScannersTCP                                                                 string `json:"network_scanners.tcp,omitempty"`
					LocalPortscanSnmp                                                                  string `json:"local_portscan.snmp,omitempty"`
					PortRange                                                                          string `json:"port_range,omitempty"`
					NessusSYNScannerRadioFirewallDetection                                             string `json:"Nessus SYN scanner[radio]:Firewall detection :,omitempty"`
					PingTheRemoteHostEntryNumberOfRetriesICMP                                          string `json:"Ping the remote host[entry]:Number of retries (ICMP) :,omitempty"`
					PingTheRemoteHostEntryTCPPingDestinationPortS                                      string `json:"Ping the remote host[entry]:TCP ping destination port(s) :,omitempty"`
					PortScannersSettingsCheckboxCheckOpenTCPPortsFoundByLocalPortEnumerators           string `json:"Port scanners settings[checkbox]:Check open TCP ports found by local port enumerators,omitempty"`
					LocalPortscanNetstatWmi                                                            string `json:"local_portscan.netstat_wmi,omitempty"`
					PingTheRemoteHostCheckboxInterpretICMPUnreachFromGateway                           string `json:"Ping the remote host[checkbox]:Interpret ICMP unreach from gateway,omitempty"`
					NetworkScannersUDP                                                                 string `json:"network_scanners.udp,omitempty"`
					PingTheRemoteHostCheckboxDoATCPPing                                                string `json:"Ping the remote host[checkbox]:Do a TCP ping,omitempty"`
					NetworkScannersSyn                                                                 string `json:"network_scanners.syn,omitempty"`
					NessusTCPScannerRadioFirewallDetection                                             string `json:"Nessus TCP scanner[radio]:Firewall detection :,omitempty"`
					PluginSelectionIndividualPlugin11219                                               string `json:"plugin_selection.individual_plugin.11219,omitempty"`
					PluginSelectionIndividualPlugin14272                                               string `json:"plugin_selection.individual_plugin.14272,omitempty"`
					WakeOnLANEntryTimeToWaitInMinutesForTheSystemsToBoot                               string `json:"Wake-on-LAN[entry]:Time to wait (in minutes) for the systems to boot:,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNovellNetwareHosts                              string `json:"Do not scan fragile devices[checkbox]:Scan Novell Netware hosts,omitempty"`
					PingTheRemoteHostCheckboxTestTheLocalNessusHost                                    string `json:"Ping the remote host[checkbox]:Test the local Nessus host,omitempty"`
					UnscannedClosed                                                                    string `json:"unscanned_closed,omitempty"`
					GlobalVariableSettingsRadioNetworkType                                             string `json:"Global variable settings[radio]:Network type,omitempty"`
					PingTheRemoteHostCheckboxFastNetworkDiscovery                                      string `json:"Ping the remote host[checkbox]:Fast network discovery,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNetworkPrinters                                 string `json:"Do not scan fragile devices[checkbox]:Scan Network Printers,omitempty"`
				} `json:"preferences,omitempty"`
				Preferences4 struct {
					PluginSelectionIndividualPlugin34220                                               string `json:"plugin_selection.individual_plugin.34220,omitempty"`
					WakeOnLANFileListOfMACAddressesForWakeOnLAN                                        string `json:"Wake-on-LAN[file]:List of MAC addresses for Wake-on-LAN:,omitempty"`
					PingTheRemoteHostCheckboxDoAnICMPPing                                              string `json:"Ping the remote host[checkbox]:Do an ICMP ping,omitempty"`
					PluginSelectionIndividualPlugin14274                                               string `json:"plugin_selection.individual_plugin.14274,omitempty"`
					PortscanPing                                                                       string `json:"portscan.ping,omitempty"`
					PortScannersSettingsCheckboxOnlyRunNetworkPortScannersIfLocalPortEnumerationFailed string `json:"Port scanners settings[checkbox]:Only run network port scanners if local port enumeration failed,omitempty"`
					PingTheRemoteHostCheckboxDoAnARPPing                                               string `json:"Ping the remote host[checkbox]:Do an ARP ping,omitempty"`
					PingTheRemoteHostCheckboxDoAnApplicativeUDPPingDNSRPC                              string `json:"Ping the remote host[checkbox]:Do an applicative UDP ping (DNS,RPC...),omitempty"`
					LocalPortscanNetstatSSH                                                            string `json:"local_portscan.netstat_ssh,omitempty"`
					PluginSelectionIndividualPlugin10180                                               string `json:"plugin_selection.individual_plugin.10180,omitempty"`
					NetworkScannersTCP                                                                 string `json:"network_scanners.tcp,omitempty"`
					LocalPortscanSnmp                                                                  string `json:"local_portscan.snmp,omitempty"`
					PortRange                                                                          string `json:"port_range,omitempty"`
					NessusSYNScannerRadioFirewallDetection                                             string `json:"Nessus SYN scanner[radio]:Firewall detection :,omitempty"`
					PingTheRemoteHostEntryNumberOfRetriesICMP                                          string `json:"Ping the remote host[entry]:Number of retries (ICMP) :,omitempty"`
					PingTheRemoteHostEntryTCPPingDestinationPortS                                      string `json:"Ping the remote host[entry]:TCP ping destination port(s) :,omitempty"`
					PortScannersSettingsCheckboxCheckOpenTCPPortsFoundByLocalPortEnumerators           string `json:"Port scanners settings[checkbox]:Check open TCP ports found by local port enumerators,omitempty"`
					LocalPortscanNetstatWmi                                                            string `json:"local_portscan.netstat_wmi,omitempty"`
					PingTheRemoteHostCheckboxInterpretICMPUnreachFromGateway                           string `json:"Ping the remote host[checkbox]:Interpret ICMP unreach from gateway,omitempty"`
					NetworkScannersUDP                                                                 string `json:"network_scanners.udp,omitempty"`
					PingTheRemoteHostCheckboxDoATCPPing                                                string `json:"Ping the remote host[checkbox]:Do a TCP ping,omitempty"`
					NetworkScannersSyn                                                                 string `json:"network_scanners.syn,omitempty"`
					NessusTCPScannerRadioFirewallDetection                                             string `json:"Nessus TCP scanner[radio]:Firewall detection :,omitempty"`
					PluginSelectionIndividualPlugin11219                                               string `json:"plugin_selection.individual_plugin.11219,omitempty"`
					PluginSelectionIndividualPlugin14272                                               string `json:"plugin_selection.individual_plugin.14272,omitempty"`
					WakeOnLANEntryTimeToWaitInMinutesForTheSystemsToBoot                               string `json:"Wake-on-LAN[entry]:Time to wait (in minutes) for the systems to boot:,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNovellNetwareHosts                              string `json:"Do not scan fragile devices[checkbox]:Scan Novell Netware hosts,omitempty"`
					PingTheRemoteHostCheckboxTestTheLocalNessusHost                                    string `json:"Ping the remote host[checkbox]:Test the local Nessus host,omitempty"`
					UnscannedClosed                                                                    string `json:"unscanned_closed,omitempty"`
					PingTheRemoteHostCheckboxFastNetworkDiscovery                                      string `json:"Ping the remote host[checkbox]:Fast network discovery,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNetworkPrinters                                 string `json:"Do not scan fragile devices[checkbox]:Scan Network Printers,omitempty"`
				} `json:"preferences,omitempty"`
				Preferences5 struct {
					PluginSelectionIndividualPlugin34220                                               string `json:"plugin_selection.individual_plugin.34220,omitempty"`
					WakeOnLANFileListOfMACAddressesForWakeOnLAN                                        string `json:"Wake-on-LAN[file]:List of MAC addresses for Wake-on-LAN:,omitempty"`
					PingTheRemoteHostCheckboxDoAnICMPPing                                              string `json:"Ping the remote host[checkbox]:Do an ICMP ping,omitempty"`
					PluginSelectionIndividualPlugin14274                                               string `json:"plugin_selection.individual_plugin.14274,omitempty"`
					PortscanPing                                                                       string `json:"portscan.ping,omitempty"`
					PortScannersSettingsCheckboxOnlyRunNetworkPortScannersIfLocalPortEnumerationFailed string `json:"Port scanners settings[checkbox]:Only run network port scanners if local port enumeration failed,omitempty"`
					PingTheRemoteHostCheckboxDoAnARPPing                                               string `json:"Ping the remote host[checkbox]:Do an ARP ping,omitempty"`
					PingTheRemoteHostCheckboxDoAnApplicativeUDPPingDNSRPC                              string `json:"Ping the remote host[checkbox]:Do an applicative UDP ping (DNS,RPC...),omitempty"`
					LocalPortscanNetstatSSH                                                            string `json:"local_portscan.netstat_ssh,omitempty"`
					PluginSelectionIndividualPlugin10180                                               string `json:"plugin_selection.individual_plugin.10180,omitempty"`
					NetworkScannersTCP                                                                 string `json:"network_scanners.tcp,omitempty"`
					LocalPortscanSnmp                                                                  string `json:"local_portscan.snmp,omitempty"`
					PortRange                                                                          string `json:"port_range,omitempty"`
					NessusSYNScannerRadioFirewallDetection                                             string `json:"Nessus SYN scanner[radio]:Firewall detection :,omitempty"`
					PingTheRemoteHostEntryNumberOfRetriesICMP                                          string `json:"Ping the remote host[entry]:Number of retries (ICMP) :,omitempty"`
					PingTheRemoteHostEntryTCPPingDestinationPortS                                      string `json:"Ping the remote host[entry]:TCP ping destination port(s) :,omitempty"`
					PortScannersSettingsCheckboxCheckOpenTCPPortsFoundByLocalPortEnumerators           string `json:"Port scanners settings[checkbox]:Check open TCP ports found by local port enumerators,omitempty"`
					LocalPortscanNetstatWmi                                                            string `json:"local_portscan.netstat_wmi,omitempty"`
					PingTheRemoteHostCheckboxInterpretICMPUnreachFromGateway                           string `json:"Ping the remote host[checkbox]:Interpret ICMP unreach from gateway,omitempty"`
					NetworkScannersUDP                                                                 string `json:"network_scanners.udp,omitempty"`
					PingTheRemoteHostCheckboxDoATCPPing                                                string `json:"Ping the remote host[checkbox]:Do a TCP ping,omitempty"`
					NetworkScannersSyn                                                                 string `json:"network_scanners.syn,omitempty"`
					NessusTCPScannerRadioFirewallDetection                                             string `json:"Nessus TCP scanner[radio]:Firewall detection :,omitempty"`
					PluginSelectionIndividualPlugin11219                                               string `json:"plugin_selection.individual_plugin.11219,omitempty"`
					PluginSelectionIndividualPlugin14272                                               string `json:"plugin_selection.individual_plugin.14272,omitempty"`
					WakeOnLANEntryTimeToWaitInMinutesForTheSystemsToBoot                               string `json:"Wake-on-LAN[entry]:Time to wait (in minutes) for the systems to boot:,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNovellNetwareHosts                              string `json:"Do not scan fragile devices[checkbox]:Scan Novell Netware hosts,omitempty"`
					PingTheRemoteHostCheckboxTestTheLocalNessusHost                                    string `json:"Ping the remote host[checkbox]:Test the local Nessus host,omitempty"`
					UnscannedClosed                                                                    string `json:"unscanned_closed,omitempty"`
					PingTheRemoteHostCheckboxFastNetworkDiscovery                                      string `json:"Ping the remote host[checkbox]:Fast network discovery,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNetworkPrinters                                 string `json:"Do not scan fragile devices[checkbox]:Scan Network Printers,omitempty"`
				} `json:"preferences,omitempty"`
				Preferences6 struct {
					PluginSelectionIndividualPlugin34220                            string `json:"plugin_selection.individual_plugin.34220,omitempty"`
					PingTheRemoteHostCheckboxDoAnICMPPing                           string `json:"Ping the remote host[checkbox]:Do an ICMP ping,omitempty"`
					PluginSelectionIndividualPlugin14274                            string `json:"plugin_selection.individual_plugin.14274,omitempty"`
					PortscanPing                                                    string `json:"portscan.ping,omitempty"`
					PingTheRemoteHostCheckboxDoAnARPPing                            string `json:"Ping the remote host[checkbox]:Do an ARP ping,omitempty"`
					PingTheRemoteHostCheckboxDoAnApplicativeUDPPingDNSRPC           string `json:"Ping the remote host[checkbox]:Do an applicative UDP ping (DNS,RPC...),omitempty"`
					DoNotScanFragileDevicesCheckboxScanOperationalTechnologyDevices string `json:"Do not scan fragile devices[checkbox]:Scan Operational Technology devices,omitempty"`
					LocalPortscanNetstatSSH                                         string `json:"local_portscan.netstat_ssh,omitempty"`
					PluginSelectionIndividualPlugin10180                            string `json:"plugin_selection.individual_plugin.10180,omitempty"`
					LocalPortscanSnmp                                               string `json:"local_portscan.snmp,omitempty"`
					PingTheRemoteHostEntryNumberOfRetriesICMP                       string `json:"Ping the remote host[entry]:Number of retries (ICMP) :,omitempty"`
					LocalPortscanNetstatWmi                                         string `json:"local_portscan.netstat_wmi,omitempty"`
					PingTheRemoteHostCheckboxInterpretICMPUnreachFromGateway        string `json:"Ping the remote host[checkbox]:Interpret ICMP unreach from gateway,omitempty"`
					PingTheRemoteHostCheckboxDoATCPPing                             string `json:"Ping the remote host[checkbox]:Do a TCP ping,omitempty"`
					PluginSelectionIndividualPlugin14272                            string `json:"plugin_selection.individual_plugin.14272,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNovellNetwareHosts           string `json:"Do not scan fragile devices[checkbox]:Scan Novell Netware hosts,omitempty"`
					PingTheRemoteHostCheckboxTestTheLocalNessusHost                 string `json:"Ping the remote host[checkbox]:Test the local Nessus host,omitempty"`
					GlobalVariableSettingsRadioNetworkType                          string `json:"Global variable settings[radio]:Network type,omitempty"`
					PingTheRemoteHostCheckboxFastNetworkDiscovery                   string `json:"Ping the remote host[checkbox]:Fast network discovery,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNetworkPrinters              string `json:"Do not scan fragile devices[checkbox]:Scan Network Printers,omitempty"`
				} `json:"preferences,omitempty"`
				Preferences7 struct {
					PluginSelectionIndividualPlugin34220                            string `json:"plugin_selection.individual_plugin.34220,omitempty"`
					PingTheRemoteHostCheckboxDoAnICMPPing                           string `json:"Ping the remote host[checkbox]:Do an ICMP ping,omitempty"`
					PluginSelectionIndividualPlugin14274                            string `json:"plugin_selection.individual_plugin.14274,omitempty"`
					PortscanPing                                                    string `json:"portscan.ping,omitempty"`
					PingTheRemoteHostCheckboxDoAnARPPing                            string `json:"Ping the remote host[checkbox]:Do an ARP ping,omitempty"`
					PingTheRemoteHostCheckboxDoAnApplicativeUDPPingDNSRPC           string `json:"Ping the remote host[checkbox]:Do an applicative UDP ping (DNS,RPC...),omitempty"`
					DoNotScanFragileDevicesCheckboxScanOperationalTechnologyDevices string `json:"Do not scan fragile devices[checkbox]:Scan Operational Technology devices,omitempty"`
					LocalPortscanNetstatSSH                                         string `json:"local_portscan.netstat_ssh,omitempty"`
					PluginSelectionIndividualPlugin10180                            string `json:"plugin_selection.individual_plugin.10180,omitempty"`
					NetworkScannersTCP                                              string `json:"network_scanners.tcp,omitempty"`
					LocalPortscanSnmp                                               string `json:"local_portscan.snmp,omitempty"`
					PortRange                                                       string `json:"port_range,omitempty"`
					NessusSYNScannerRadioFirewallDetection                          string `json:"Nessus SYN scanner[radio]:Firewall detection :,omitempty"`
					PingTheRemoteHostEntryNumberOfRetriesICMP                       string `json:"Ping the remote host[entry]:Number of retries (ICMP) :,omitempty"`
					PingTheRemoteHostEntryTCPPingDestinationPortS                   string `json:"Ping the remote host[entry]:TCP ping destination port(s) :,omitempty"`
					LocalPortscanNetstatWmi                                         string `json:"local_portscan.netstat_wmi,omitempty"`
					PingTheRemoteHostCheckboxInterpretICMPUnreachFromGateway        string `json:"Ping the remote host[checkbox]:Interpret ICMP unreach from gateway,omitempty"`
					NetworkScannersUDP                                              string `json:"network_scanners.udp,omitempty"`
					PingTheRemoteHostCheckboxDoATCPPing                             string `json:"Ping the remote host[checkbox]:Do a TCP ping,omitempty"`
					NetworkScannersSyn                                              string `json:"network_scanners.syn,omitempty"`
					NessusTCPScannerRadioFirewallDetection                          string `json:"Nessus TCP scanner[radio]:Firewall detection :,omitempty"`
					PluginSelectionIndividualPlugin11219                            string `json:"plugin_selection.individual_plugin.11219,omitempty"`
					PluginSelectionIndividualPlugin14272                            string `json:"plugin_selection.individual_plugin.14272,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNovellNetwareHosts           string `json:"Do not scan fragile devices[checkbox]:Scan Novell Netware hosts,omitempty"`
					PingTheRemoteHostCheckboxTestTheLocalNessusHost                 string `json:"Ping the remote host[checkbox]:Test the local Nessus host,omitempty"`
					UnscannedClosed                                                 string `json:"unscanned_closed,omitempty"`
					GlobalVariableSettingsRadioNetworkType                          string `json:"Global variable settings[radio]:Network type,omitempty"`
					PingTheRemoteHostCheckboxFastNetworkDiscovery                   string `json:"Ping the remote host[checkbox]:Fast network discovery,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNetworkPrinters              string `json:"Do not scan fragile devices[checkbox]:Scan Network Printers,omitempty"`
				} `json:"preferences,omitempty"`
				Preferences8 struct {
					PingTheRemoteHostCheckboxDoAnICMPPing           string `json:"Ping the remote host[checkbox]:Do an ICMP ping,omitempty"`
					PortscanPing                                    string `json:"portscan.ping,omitempty"`
					PingTheRemoteHostCheckboxDoAnARPPing            string `json:"Ping the remote host[checkbox]:Do an ARP ping,omitempty"`
					PluginSelectionIndividualPlugin10180            string `json:"plugin_selection.individual_plugin.10180,omitempty"`
					PluginSelectionIndividualPlugin11936            string `json:"plugin_selection.individual_plugin.11936,omitempty"`
					PingTheRemoteHostCheckboxDoATCPPing             string `json:"Ping the remote host[checkbox]:Do a TCP ping,omitempty"`
					PingTheRemoteHostCheckboxTestTheLocalNessusHost string `json:"Ping the remote host[checkbox]:Test the local Nessus host,omitempty"`
					PingTheRemoteHostCheckboxFastNetworkDiscovery   string `json:"Ping the remote host[checkbox]:Fast network discovery,omitempty"`
				} `json:"preferences,omitempty"`
				Preferences9 struct {
					PluginSelectionIndividualPlugin34220                                               string `json:"plugin_selection.individual_plugin.34220,omitempty"`
					WakeOnLANFileListOfMACAddressesForWakeOnLAN                                        string `json:"Wake-on-LAN[file]:List of MAC addresses for Wake-on-LAN:,omitempty"`
					PingTheRemoteHostCheckboxDoAnICMPPing                                              string `json:"Ping the remote host[checkbox]:Do an ICMP ping,omitempty"`
					PluginSelectionIndividualPlugin14274                                               string `json:"plugin_selection.individual_plugin.14274,omitempty"`
					PortscanPing                                                                       string `json:"portscan.ping,omitempty"`
					PortScannersSettingsCheckboxOnlyRunNetworkPortScannersIfLocalPortEnumerationFailed string `json:"Port scanners settings[checkbox]:Only run network port scanners if local port enumeration failed,omitempty"`
					PingTheRemoteHostCheckboxDoAnARPPing                                               string `json:"Ping the remote host[checkbox]:Do an ARP ping,omitempty"`
					PingTheRemoteHostCheckboxDoAnApplicativeUDPPingDNSRPC                              string `json:"Ping the remote host[checkbox]:Do an applicative UDP ping (DNS,RPC...),omitempty"`
					LocalPortscanNetstatSSH                                                            string `json:"local_portscan.netstat_ssh,omitempty"`
					PluginSelectionIndividualPlugin10180                                               string `json:"plugin_selection.individual_plugin.10180,omitempty"`
					NetworkScannersTCP                                                                 string `json:"network_scanners.tcp,omitempty"`
					LocalPortscanSnmp                                                                  string `json:"local_portscan.snmp,omitempty"`
					PortRange                                                                          string `json:"port_range,omitempty"`
					NessusSYNScannerRadioFirewallDetection                                             string `json:"Nessus SYN scanner[radio]:Firewall detection :,omitempty"`
					PingTheRemoteHostEntryNumberOfRetriesICMP                                          string `json:"Ping the remote host[entry]:Number of retries (ICMP) :,omitempty"`
					PingTheRemoteHostEntryTCPPingDestinationPortS                                      string `json:"Ping the remote host[entry]:TCP ping destination port(s) :,omitempty"`
					PortScannersSettingsCheckboxCheckOpenTCPPortsFoundByLocalPortEnumerators           string `json:"Port scanners settings[checkbox]:Check open TCP ports found by local port enumerators,omitempty"`
					LocalPortscanNetstatWmi                                                            string `json:"local_portscan.netstat_wmi,omitempty"`
					PingTheRemoteHostCheckboxInterpretICMPUnreachFromGateway                           string `json:"Ping the remote host[checkbox]:Interpret ICMP unreach from gateway,omitempty"`
					NetworkScannersUDP                                                                 string `json:"network_scanners.udp,omitempty"`
					PingTheRemoteHostCheckboxDoATCPPing                                                string `json:"Ping the remote host[checkbox]:Do a TCP ping,omitempty"`
					NetworkScannersSyn                                                                 string `json:"network_scanners.syn,omitempty"`
					NessusTCPScannerRadioFirewallDetection                                             string `json:"Nessus TCP scanner[radio]:Firewall detection :,omitempty"`
					PluginSelectionIndividualPlugin11219                                               string `json:"plugin_selection.individual_plugin.11219,omitempty"`
					PluginSelectionIndividualPlugin14272                                               string `json:"plugin_selection.individual_plugin.14272,omitempty"`
					WakeOnLANEntryTimeToWaitInMinutesForTheSystemsToBoot                               string `json:"Wake-on-LAN[entry]:Time to wait (in minutes) for the systems to boot:,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNovellNetwareHosts                              string `json:"Do not scan fragile devices[checkbox]:Scan Novell Netware hosts,omitempty"`
					PingTheRemoteHostCheckboxTestTheLocalNessusHost                                    string `json:"Ping the remote host[checkbox]:Test the local Nessus host,omitempty"`
					UnscannedClosed                                                                    string `json:"unscanned_closed,omitempty"`
					GlobalVariableSettingsRadioNetworkType                                             string `json:"Global variable settings[radio]:Network type,omitempty"`
					PingTheRemoteHostCheckboxFastNetworkDiscovery                                      string `json:"Ping the remote host[checkbox]:Fast network discovery,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNetworkPrinters                                 string `json:"Do not scan fragile devices[checkbox]:Scan Network Printers,omitempty"`
				} `json:"preferences,omitempty"`
				Preferences10 struct {
					PluginSelectionIndividualPlugin34220                                               string `json:"plugin_selection.individual_plugin.34220,omitempty"`
					WakeOnLANFileListOfMACAddressesForWakeOnLAN                                        string `json:"Wake-on-LAN[file]:List of MAC addresses for Wake-on-LAN:,omitempty"`
					PingTheRemoteHostCheckboxDoAnICMPPing                                              string `json:"Ping the remote host[checkbox]:Do an ICMP ping,omitempty"`
					PluginSelectionIndividualPlugin14274                                               string `json:"plugin_selection.individual_plugin.14274,omitempty"`
					PortscanPing                                                                       string `json:"portscan.ping,omitempty"`
					PortScannersSettingsCheckboxOnlyRunNetworkPortScannersIfLocalPortEnumerationFailed string `json:"Port scanners settings[checkbox]:Only run network port scanners if local port enumeration failed,omitempty"`
					PingTheRemoteHostCheckboxDoAnARPPing                                               string `json:"Ping the remote host[checkbox]:Do an ARP ping,omitempty"`
					PingTheRemoteHostCheckboxDoAnApplicativeUDPPingDNSRPC                              string `json:"Ping the remote host[checkbox]:Do an applicative UDP ping (DNS,RPC...),omitempty"`
					LocalPortscanNetstatSSH                                                            string `json:"local_portscan.netstat_ssh,omitempty"`
					PluginSelectionIndividualPlugin10180                                               string `json:"plugin_selection.individual_plugin.10180,omitempty"`
					NetworkScannersTCP                                                                 string `json:"network_scanners.tcp,omitempty"`
					LocalPortscanSnmp                                                                  string `json:"local_portscan.snmp,omitempty"`
					PortRange                                                                          string `json:"port_range,omitempty"`
					NessusSYNScannerRadioFirewallDetection                                             string `json:"Nessus SYN scanner[radio]:Firewall detection :,omitempty"`
					PingTheRemoteHostEntryNumberOfRetriesICMP                                          string `json:"Ping the remote host[entry]:Number of retries (ICMP) :,omitempty"`
					PingTheRemoteHostEntryTCPPingDestinationPortS                                      string `json:"Ping the remote host[entry]:TCP ping destination port(s) :,omitempty"`
					PortScannersSettingsCheckboxCheckOpenTCPPortsFoundByLocalPortEnumerators           string `json:"Port scanners settings[checkbox]:Check open TCP ports found by local port enumerators,omitempty"`
					LocalPortscanNetstatWmi                                                            string `json:"local_portscan.netstat_wmi,omitempty"`
					PingTheRemoteHostCheckboxInterpretICMPUnreachFromGateway                           string `json:"Ping the remote host[checkbox]:Interpret ICMP unreach from gateway,omitempty"`
					NetworkScannersUDP                                                                 string `json:"network_scanners.udp,omitempty"`
					PingTheRemoteHostCheckboxDoATCPPing                                                string `json:"Ping the remote host[checkbox]:Do a TCP ping,omitempty"`
					NetworkScannersSyn                                                                 string `json:"network_scanners.syn,omitempty"`
					NessusTCPScannerRadioFirewallDetection                                             string `json:"Nessus TCP scanner[radio]:Firewall detection :,omitempty"`
					PluginSelectionIndividualPlugin11219                                               string `json:"plugin_selection.individual_plugin.11219,omitempty"`
					PluginSelectionIndividualPlugin14272                                               string `json:"plugin_selection.individual_plugin.14272,omitempty"`
					WakeOnLANEntryTimeToWaitInMinutesForTheSystemsToBoot                               string `json:"Wake-on-LAN[entry]:Time to wait (in minutes) for the systems to boot:,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNovellNetwareHosts                              string `json:"Do not scan fragile devices[checkbox]:Scan Novell Netware hosts,omitempty"`
					PingTheRemoteHostCheckboxTestTheLocalNessusHost                                    string `json:"Ping the remote host[checkbox]:Test the local Nessus host,omitempty"`
					UnscannedClosed                                                                    string `json:"unscanned_closed,omitempty"`
					GlobalVariableSettingsRadioNetworkType                                             string `json:"Global variable settings[radio]:Network type,omitempty"`
					PingTheRemoteHostCheckboxFastNetworkDiscovery                                      string `json:"Ping the remote host[checkbox]:Fast network discovery,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNetworkPrinters                                 string `json:"Do not scan fragile devices[checkbox]:Scan Network Printers,omitempty"`
				} `json:"preferences,omitempty"`
				Preferences11 struct {
					WakeOnLANFileListOfMACAddressesForWakeOnLAN                                        string `json:"Wake-on-LAN[file]:List of MAC addresses for Wake-on-LAN:,omitempty"`
					PingTheRemoteHostCheckboxDoAnICMPPing                                              string `json:"Ping the remote host[checkbox]:Do an ICMP ping,omitempty"`
					PortscanPing                                                                       string `json:"portscan.ping,omitempty"`
					PortScannersSettingsCheckboxOnlyRunNetworkPortScannersIfLocalPortEnumerationFailed string `json:"Port scanners settings[checkbox]:Only run network port scanners if local port enumeration failed,omitempty"`
					PingTheRemoteHostCheckboxDoAnARPPing                                               string `json:"Ping the remote host[checkbox]:Do an ARP ping,omitempty"`
					PingTheRemoteHostCheckboxDoAnApplicativeUDPPingDNSRPC                              string `json:"Ping the remote host[checkbox]:Do an applicative UDP ping (DNS,RPC...),omitempty"`
					LocalPortscanNetstatSSH                                                            string `json:"local_portscan.netstat_ssh,omitempty"`
					PluginSelectionIndividualPlugin10180                                               string `json:"plugin_selection.individual_plugin.10180,omitempty"`
					NetworkScannersTCP                                                                 string `json:"network_scanners.tcp,omitempty"`
					LocalPortscanSnmp                                                                  string `json:"local_portscan.snmp,omitempty"`
					PortRange                                                                          string `json:"port_range,omitempty"`
					NessusSYNScannerRadioFirewallDetection                                             string `json:"Nessus SYN scanner[radio]:Firewall detection :,omitempty"`
					PingTheRemoteHostEntryNumberOfRetriesICMP                                          string `json:"Ping the remote host[entry]:Number of retries (ICMP) :,omitempty"`
					PingTheRemoteHostEntryTCPPingDestinationPortS                                      string `json:"Ping the remote host[entry]:TCP ping destination port(s) :,omitempty"`
					PortScannersSettingsCheckboxCheckOpenTCPPortsFoundByLocalPortEnumerators           string `json:"Port scanners settings[checkbox]:Check open TCP ports found by local port enumerators,omitempty"`
					LocalPortscanNetstatWmi                                                            string `json:"local_portscan.netstat_wmi,omitempty"`
					PingTheRemoteHostCheckboxInterpretICMPUnreachFromGateway                           string `json:"Ping the remote host[checkbox]:Interpret ICMP unreach from gateway,omitempty"`
					NetworkScannersUDP                                                                 string `json:"network_scanners.udp,omitempty"`
					PingTheRemoteHostCheckboxDoATCPPing                                                string `json:"Ping the remote host[checkbox]:Do a TCP ping,omitempty"`
					NetworkScannersSyn                                                                 string `json:"network_scanners.syn,omitempty"`
					NessusTCPScannerRadioFirewallDetection                                             string `json:"Nessus TCP scanner[radio]:Firewall detection :,omitempty"`
					PluginSelectionIndividualPlugin11219                                               string `json:"plugin_selection.individual_plugin.11219,omitempty"`
					WakeOnLANEntryTimeToWaitInMinutesForTheSystemsToBoot                               string `json:"Wake-on-LAN[entry]:Time to wait (in minutes) for the systems to boot:,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNovellNetwareHosts                              string `json:"Do not scan fragile devices[checkbox]:Scan Novell Netware hosts,omitempty"`
					PingTheRemoteHostCheckboxTestTheLocalNessusHost                                    string `json:"Ping the remote host[checkbox]:Test the local Nessus host,omitempty"`
					UnscannedClosed                                                                    string `json:"unscanned_closed,omitempty"`
					GlobalVariableSettingsRadioNetworkType                                             string `json:"Global variable settings[radio]:Network type,omitempty"`
					PingTheRemoteHostCheckboxFastNetworkDiscovery                                      string `json:"Ping the remote host[checkbox]:Fast network discovery,omitempty"`
					DoNotScanFragileDevicesCheckboxScanNetworkPrinters                                 string `json:"Do not scan fragile devices[checkbox]:Scan Network Printers,omitempty"`
				} `json:"preferences,omitempty"`
				Custom bool `json:"custom,omitempty"`
			} `json:"modes,omitempty"`
			Title  string `json:"title,omitempty"`
			Groups []struct {
				Inputs []struct {
					Type    string `json:"type,omitempty"`
					Name    string `json:"name,omitempty"`
					ID      string `json:"id,omitempty"`
					Default string `json:"default,omitempty"`
					Options []struct {
						Inputs   any    `json:"inputs,omitempty"`
						Name     string `json:"name,omitempty"`
						Sections []struct {
							Inputs []struct {
								Type    string `json:"type,omitempty"`
								ID      string `json:"id,omitempty"`
								Label   string `json:"label,omitempty"`
								Default string `json:"default,omitempty"`
								NoMsp   bool   `json:"no_msp,omitempty"`
								Hint    string `json:"hint,omitempty"`
							} `json:"inputs,omitempty"`
							Title string `json:"title,omitempty"`
							Name  string `json:"name,omitempty"`
						} `json:"sections,omitempty"`
					} `json:"options,omitempty"`
					Hint string `json:"hint,omitempty"`
				} `json:"inputs,omitempty"`
				Title    string `json:"title,omitempty"`
				Name     string `json:"name,omitempty"`
				Sections []struct {
					Inputs []struct {
						Type    string `json:"type,omitempty"`
						ID      string `json:"id,omitempty"`
						Label   string `json:"label,omitempty"`
						Default string `json:"default,omitempty"`
						Hint    string `json:"hint,omitempty"`
					} `json:"inputs,omitempty"`
					Title string `json:"title,omitempty"`
					Name  string `json:"name,omitempty"`
				} `json:"sections,omitempty"`
			} `json:"groups,omitempty"`
			Sections []any `json:"sections,omitempty"`
		} `json:"discovery,omitempty"`
		Report struct {
			Inputs any `json:"inputs,omitempty"`
			Modes  []struct {
				Desc    string `json:"desc,omitempty"`
				ID      string `json:"id,omitempty"`
				Name    string `json:"name,omitempty"`
				Default bool   `json:"default,omitempty"`
				Custom  bool   `json:"custom,omitempty"`
			} `json:"modes,omitempty"`
			Title    string `json:"title,omitempty"`
			Groups   []any  `json:"groups,omitempty"`
			Sections []struct {
				Inputs []struct {
					Type          string   `json:"type,omitempty"`
					ID            string   `json:"id,omitempty"`
					Label         string   `json:"label,omitempty"`
					Default       string   `json:"default,omitempty"`
					Options       []string `json:"options,omitempty"`
					OptionsLabels []string `json:"optionsLabels,omitempty"`
					Hint          string   `json:"hint,omitempty"`
				} `json:"inputs,omitempty"`
				Title string `json:"title,omitempty"`
				Name  string `json:"name,omitempty"`
			} `json:"sections,omitempty"`
		} `json:"report,omitempty"`
	} `json:"settings,omitempty"`
	Name string `json:"name,omitempty"`
}

func (c *Client) EditorDetails(editorType EditorType, templateUUID string) (*EditorDetailsResponse, error) {
	resp, err := c.Get(c.apiURL + "/editor/" + string(editorType) + "/templates" + templateUUID)
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

	var data EditorDetailsResponse
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return &data, nil
}
