package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type AdvanceModelPreference map[string]struct {
	HostTagging                   string `json:"host_tagging,omitempty"`
	ChecksReadTimeout             string `json:"checks_read_timeout,omitempty"`
	MaxChecks                     string `json:"max_checks,omitempty"`
	ReduceConnectionsOnCongestion string `json:"reduce_connections_on_congestion,omitempty"`
	MaxHosts                      string `json:"max_hosts,omitempty"`
}

type AssessmentModelPreference map[string]struct {
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
}

type DiscoveryModelPreference map[string]struct {
	PluginSelectionIndividualPlugin11936                                               string `json:"plugin_selection.individual_plugin.11936,omitempty"`
	DoNotScanFragileDevicesCheckboxScanOperationalTechnologyDevices                    string `json:"Do not scan fragile devices[checkbox]:Scan Operational Technology devices,omitempty"`
	GlobalVariableSettingsCheckboxThoroughTestsSlow                                    string `json:"Global variable settings[checkbox]:Thorough tests (slow),omitempty"`
	TestSSLBasedServices                                                               string `json:"Test SSL based services,omitempty"`
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
}

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
		Families map[string]struct {
			Count  int    `json:"count,omitempty"`
			ID     int    `json:"id,omitempty"`
			Locked bool   `json:"locked,omitempty"`
			Status string `json:"status,omitempty"`
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
				Desc                   string `json:"desc,omitempty"`
				ID                     string `json:"id,omitempty"`
				Name                   string `json:"name,omitempty"`
				DescIo                 string `json:"desc_io,omitempty"`
				Default                bool   `json:"default,omitempty"`
				Custom                 bool   `json:"custom,omitempty"`
				AdvanceModelPreference `json:"compliance_setting_advance_model_preference,omitempty"`
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
				Desc                      string `json:"desc,omitempty"`
				ID                        string `json:"id,omitempty"`
				Name                      string `json:"name,omitempty"`
				Default                   bool   `json:"default,omitempty"`
				Custom                    string `json:"custom,omitempty"`
				AssessmentModelPreference `json:"assessment_model_preference,omitempty"`
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
				Desc                     string `json:"desc,omitempty"`
				ID                       string `json:"id,omitempty"`
				Name                     string `json:"name,omitempty"`
				Default                  bool   `json:"default,omitempty"`
				Custom                   bool   `json:"custom,omitempty"`
				DiscoveryModelPreference `json:"discovery_model_preference"`
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

func (c *Client) EditorDetails(editorType EditorType, templateUUID string) (map[string]any, error) {
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

	var data map[string]any
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return data, nil
}
