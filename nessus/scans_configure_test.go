package nessus

import (
	"fmt"
	"testing"

	"github.com/bytedance/sonic"
)

func TestClient_ScansConfigure(t *testing.T) {
	tests := []struct {
		name    string
		options []Option
		scanID  int
		request *ScansConfigureRequest
		wantErr bool
	}{
		{
			name: "success configuration update with API key",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"ede55bc4fbad66a41a46f4a5ff35500e7485adae1bc5d94d98e9a1c1f7bb0ecc",
					"af2ca8def3fa67705e38ded764d3c282fb7f82a516883bb4f1e310aba02f1e1b",
				),
			},
			scanID: 1,
			request: &ScansConfigureRequest{
				UUID: "test-uuid",
				Settings: &ScansConfigureSetting{
					Name:        "Test Scan",
					Description: "Test Description",
					PolicyID:    1,
					FolderID:    2,
					Enabled:     true,
					Launch:      "ONETIME",
					TextTargets: []string{"192.168.1.1"},
				},
			},
			wantErr: false,
		},
		{
			name: "success configuration update with session token",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("valid-session-token"),
			},
			scanID: 1,
			request: &ScansConfigureRequest{
				UUID: "test-uuid",
				Settings: &ScansConfigureSetting{
					Name:        "Token Auth Test",
					Description: "Test with token authentication",
					PolicyID:    1,
					TextTargets: []string{"10.0.0.1"},
				},
			},
			wantErr: false,
		},
		{
			name: "success with complete configuration",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"ede55bc4fbad66a41a46f4a5ff35500e7485adae1bc5d94d98e9a1c1f7bb0ecc",
					"af2ca8def3fa67705e38ded764d3c282fb7f82a516883bb4f1e310aba02f1e1b",
				),
			},
			scanID: 10,
			request: &ScansConfigureRequest{
				UUID: "complete-test-uuid",
				Settings: &ScansConfigureSetting{
					Name:         "Complete Configuration Test",
					Description:  "Full configuration with all parameters",
					PolicyID:     5,
					FolderID:     3,
					ScannerID:    2,
					Enabled:      true,
					Launch:       "RECURRING",
					Starttime:    "20240101T120000",
					Rrules:       "FREQ=WEEKLY;INTERVAL=1;BYDAY=MO",
					Timezone:     "America/New_York",
					TargetGroups: []string{"group1", "group2"},
					AgentGroups:  []string{"agent1", "agent2"},
					TextTargets:  []string{"192.168.1.0/24", "10.0.0.0/8"},
					FileTargets:  []string{"targets.txt"},
					Emails:       "admin@example.com,user@example.com",
					Acls: []*PermissionResource{
						{
							Type:        "user",
							Permissions: 64,
							ID:          123,
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "error invalid scan ID negative",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"ede55bc4fbad66a41a46f4a5ff35500e7485adae1bc5d94d98e9a1c1f7bb0ecc",
					"af2ca8def3fa67705e38ded764d3c282fb7f82a516883bb4f1e310aba02f1e1b",
				),
			},
			scanID: -1,
			request: &ScansConfigureRequest{
				UUID: "test-uuid",
				Settings: &ScansConfigureSetting{
					Name: "Test Scan",
				},
			},
			wantErr: true,
		},
		{
			name: "error invalid scan ID zero",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"ede55bc4fbad66a41a46f4a5ff35500e7485adae1bc5d94d98e9a1c1f7bb0ecc",
					"af2ca8def3fa67705e38ded764d3c282fb7f82a516883bb4f1e310aba02f1e1b",
				),
			},
			scanID: 0,
			request: &ScansConfigureRequest{
				UUID: "test-uuid",
				Settings: &ScansConfigureSetting{
					Name: "Test Scan",
				},
			},
			wantErr: true,
		},
		{
			name: "error without authentication",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
			},
			scanID: 1,
			request: &ScansConfigureRequest{
				UUID: "test-uuid",
				Settings: &ScansConfigureSetting{
					Name: "Test Scan",
				},
			},
			wantErr: true,
		},
		{
			name: "error with invalid API key",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey("invalid-key", "invalid-secret"),
			},
			scanID: 1,
			request: &ScansConfigureRequest{
				UUID: "test-uuid",
				Settings: &ScansConfigureSetting{
					Name: "Test Scan",
				},
			},
			wantErr: true,
		},
		{
			name: "error with invalid session token",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("invalid-token"),
			},
			scanID: 1,
			request: &ScansConfigureRequest{
				UUID: "test-uuid",
				Settings: &ScansConfigureSetting{
					Name: "Test Scan",
				},
			},
			wantErr: true,
		},
		{
			name: "error with expired session token",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("expired-session-token"),
			},
			scanID: 1,
			request: &ScansConfigureRequest{
				UUID: "test-uuid",
				Settings: &ScansConfigureSetting{
					Name: "Test Scan",
				},
			},
			wantErr: true,
		},
		{
			name: "error with nil request",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"ede55bc4fbad66a41a46f4a5ff35500e7485adae1bc5d94d98e9a1c1f7bb0ecc",
					"af2ca8def3fa67705e38ded764d3c282fb7f82a516883bb4f1e310aba02f1e1b",
				),
			},
			scanID:  1,
			request: nil,
			wantErr: true,
		},
		{
			name: "error with nil settings",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"ede55bc4fbad66a41a46f4a5ff35500e7485adae1bc5d94d98e9a1c1f7bb0ecc",
					"af2ca8def3fa67705e38ded764d3c282fb7f82a516883bb4f1e310aba02f1e1b",
				),
			},
			scanID: 1,
			request: &ScansConfigureRequest{
				UUID:     "test-uuid",
				Settings: nil,
			},
			wantErr: true,
		},
		{
			name: "error unauthorized access",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"unauthorized-access-key",
					"unauthorized-secret-key",
				),
			},
			scanID: 999999,
			request: &ScansConfigureRequest{
				UUID: "test-uuid",
				Settings: &ScansConfigureSetting{
					Name: "Unauthorized Test",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(tt.options...)
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			got, err := c.ScansConfigure(tt.scanID, tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScansConfigure() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Errorf("ScansConfigure() got = %v, want non-nil", got)
			}
		})
	}
}

func TestScansConfigureRequestValidation(t *testing.T) {
	tests := []struct {
		name        string
		request     *ScansConfigureRequest
		expectValid bool
	}{
		{
			name: "valid request with all fields",
			request: &ScansConfigureRequest{
				UUID: "valid-uuid-12345",
				Settings: &ScansConfigureSetting{
					Name:         "Complete Test Scan",
					Description:  "Full configuration test",
					PolicyID:     10,
					FolderID:     5,
					ScannerID:    3,
					Enabled:      true,
					Launch:       "RECURRING",
					Starttime:    "20240101T120000",
					Rrules:       "FREQ=DAILY;INTERVAL=1",
					Timezone:     "UTC",
					TargetGroups: []string{"group1", "group2"},
					AgentGroups:  []string{"agent1", "agent2"},
					TextTargets:  []string{"192.168.1.1", "10.0.0.1"},
					FileTargets:  []string{"targets.txt", "hosts.csv"},
					Emails:       "admin@example.com",
					Acls: []*PermissionResource{
						{
							Type:        "user",
							Permissions: 64,
							ID:          123,
						},
					},
				},
			},
			expectValid: true,
		},
		{
			name: "valid request with minimal fields",
			request: &ScansConfigureRequest{
				UUID: "minimal-uuid",
				Settings: &ScansConfigureSetting{
					Name:        "Minimal Scan",
					TextTargets: []string{"127.0.0.1"},
				},
			},
			expectValid: true,
		},
		{
			name: "valid request with empty name",
			request: &ScansConfigureRequest{
				UUID: "empty-name-uuid",
				Settings: &ScansConfigureSetting{
					Name:        "",
					TextTargets: []string{"192.168.1.1"},
				},
			},
			expectValid: true, // Validation happens server-side
		},
		{
			name: "valid request with multiple target groups",
			request: &ScansConfigureRequest{
				UUID: "multi-target-uuid",
				Settings: &ScansConfigureSetting{
					Name:         "Multi Target Scan",
					TargetGroups: []string{"group1", "group2", "group3", "group4"},
					TextTargets:  []string{"10.0.0.1"},
				},
			},
			expectValid: true,
		},
		{
			name: "valid request with multiple agent groups",
			request: &ScansConfigureRequest{
				UUID: "multi-agent-uuid",
				Settings: &ScansConfigureSetting{
					Name:        "Multi Agent Scan",
					AgentGroups: []string{"agent1", "agent2", "agent3"},
					TextTargets: []string{"172.16.0.1"},
				},
			},
			expectValid: true,
		},
		{
			name: "valid request with email notifications",
			request: &ScansConfigureRequest{
				UUID: "email-uuid",
				Settings: &ScansConfigureSetting{
					Name:        "Email Notification Scan",
					Emails:      "user1@example.com,user2@example.com,admin@example.com",
					TextTargets: []string{"192.168.1.100"},
				},
			},
			expectValid: true,
		},
		{
			name: "valid request with schedule settings",
			request: &ScansConfigureRequest{
				UUID: "schedule-uuid",
				Settings: &ScansConfigureSetting{
					Name:        "Scheduled Scan",
					Launch:      "RECURRING",
					Starttime:   "20240315T140000",
					Rrules:      "FREQ=WEEKLY;INTERVAL=2;BYDAY=FR",
					Timezone:    "America/Los_Angeles",
					TextTargets: []string{"10.10.10.10"},
				},
			},
			expectValid: true,
		},
		{
			name: "valid request with ACL permissions",
			request: &ScansConfigureRequest{
				UUID: "acl-uuid",
				Settings: &ScansConfigureSetting{
					Name:        "ACL Test Scan",
					TextTargets: []string{"192.168.1.50"},
					Acls: []*PermissionResource{
						{
							Type:        "user",
							Permissions: 32,
							ID:          456,
						},
						{
							Type:        "group",
							Permissions: 16,
							ID:          789,
						},
					},
				},
			},
			expectValid: true,
		},
		{
			name: "valid request with empty arrays",
			request: &ScansConfigureRequest{
				UUID: "empty-arrays-uuid",
				Settings: &ScansConfigureSetting{
					Name:         "Empty Arrays Scan",
					TargetGroups: []string{},
					AgentGroups:  []string{},
					TextTargets:  []string{"192.168.1.200"},
					FileTargets:  []string{},
					Acls:         []*PermissionResource{},
				},
			},
			expectValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that the struct can be marshaled/unmarshaled
			data, err := sonic.Marshal(tt.request)
			if err != nil && tt.expectValid {
				t.Errorf("Expected valid request, but marshaling failed: %v", err)
				return
			}
			if err == nil && !tt.expectValid {
				t.Errorf("Expected invalid request, but marshaling succeeded")
				return
			}

			if tt.expectValid {
				var unmarshaled ScansConfigureRequest
				err = sonic.Unmarshal(data, &unmarshaled)
				if err != nil {
					t.Errorf("Failed to unmarshal valid request: %v", err)
					return
				}

				// Verify key fields are preserved
				if unmarshaled.UUID != tt.request.UUID {
					t.Errorf("UUID mismatch: got %s, want %s", unmarshaled.UUID, tt.request.UUID)
				}
				if unmarshaled.Settings != nil && tt.request.Settings != nil {
					if unmarshaled.Settings.Name != tt.request.Settings.Name {
						t.Errorf("Name mismatch: got %s, want %s", unmarshaled.Settings.Name, tt.request.Settings.Name)
					}
				}
			}
		})
	}
}

func TestScansConfigureSettingValidation(t *testing.T) {
	settings := []struct {
		name     string
		setting  *ScansConfigureSetting
		expected string
	}{
		{
			name: "basic scan setting",
			setting: &ScansConfigureSetting{
				Name:        "Basic Configuration",
				Description: "A basic scan configuration test",
				TextTargets: []string{"192.168.1.1"},
			},
			expected: "Basic Configuration",
		},
		{
			name: "setting with policy and folder",
			setting: &ScansConfigureSetting{
				Name:        "Policy and Folder Test",
				Description: "Test with specific policy and folder",
				PolicyID:    15,
				FolderID:    8,
				Enabled:     true,
				Launch:      "ONETIME",
				TextTargets: []string{"192.168.1.0/24"},
			},
			expected: "Policy and Folder Test",
		},
		{
			name: "setting with scanner specification",
			setting: &ScansConfigureSetting{
				Name:        "Scanner Specific Test",
				ScannerID:   7,
				TextTargets: []string{"10.0.0.0/16"},
			},
			expected: "Scanner Specific Test",
		},
		{
			name: "setting with target and agent groups",
			setting: &ScansConfigureSetting{
				Name:         "Group-based Scan",
				TargetGroups: []string{"WebServers", "DatabaseServers"},
				AgentGroups:  []string{"LinuxAgents", "WindowsAgents"},
			},
			expected: "Group-based Scan",
		},
		{
			name: "setting with scheduling",
			setting: &ScansConfigureSetting{
				Name:        "Scheduled Scan Test",
				Launch:      "RECURRING",
				Starttime:   "20240401T080000",
				Rrules:      "FREQ=MONTHLY;INTERVAL=1;BYMONTHDAY=1",
				Timezone:    "Europe/London",
				TextTargets: []string{"172.16.0.0/12"},
			},
			expected: "Scheduled Scan Test",
		},
		{
			name: "setting with file targets",
			setting: &ScansConfigureSetting{
				Name:        "File Target Test",
				FileTargets: []string{"production_hosts.txt", "staging_hosts.csv"},
				TextTargets: []string{"192.168.100.1"},
			},
			expected: "File Target Test",
		},
		{
			name: "setting with notifications",
			setting: &ScansConfigureSetting{
				Name:        "Notification Test",
				Emails:      "security@company.com,ops@company.com",
				TextTargets: []string{"10.20.30.40"},
			},
			expected: "Notification Test",
		},
		{
			name: "setting with complex ACLs",
			setting: &ScansConfigureSetting{
				Name:        "Complex ACL Test",
				TextTargets: []string{"172.16.1.1"},
				Acls: []*PermissionResource{
					{
						Type:        "user",
						Permissions: 128,
						ID:          1001,
					},
					{
						Type:        "group",
						Permissions: 64,
						ID:          2001,
					},
					{
						Type:        "user",
						Permissions: 32,
						ID:          1002,
					},
				},
			},
			expected: "Complex ACL Test",
		},
	}

	for _, tt := range settings {
		t.Run(tt.name, func(t *testing.T) {
			// Test marshaling
			data, err := sonic.Marshal(tt.setting)
			if err != nil {
				t.Errorf("Failed to marshal setting: %v", err)
				return
			}

			// Test unmarshaling
			var unmarshaled ScansConfigureSetting
			err = sonic.Unmarshal(data, &unmarshaled)
			if err != nil {
				t.Errorf("Failed to unmarshal setting: %v", err)
				return
			}

			if unmarshaled.Name != tt.expected {
				t.Errorf("Expected name %s, got %s", tt.expected, unmarshaled.Name)
			}

			// Verify arrays are properly handled
			if len(tt.setting.TextTargets) > 0 && len(unmarshaled.TextTargets) != len(tt.setting.TextTargets) {
				t.Errorf("TextTargets length mismatch: got %d, want %d", len(unmarshaled.TextTargets), len(tt.setting.TextTargets))
			}

			if len(tt.setting.TargetGroups) > 0 && len(unmarshaled.TargetGroups) != len(tt.setting.TargetGroups) {
				t.Errorf("TargetGroups length mismatch: got %d, want %d", len(unmarshaled.TargetGroups), len(tt.setting.TargetGroups))
			}

			if len(tt.setting.AgentGroups) > 0 && len(unmarshaled.AgentGroups) != len(tt.setting.AgentGroups) {
				t.Errorf("AgentGroups length mismatch: got %d, want %d", len(unmarshaled.AgentGroups), len(tt.setting.AgentGroups))
			}

			if len(tt.setting.Acls) > 0 && len(unmarshaled.Acls) != len(tt.setting.Acls) {
				t.Errorf("Acls length mismatch: got %d, want %d", len(unmarshaled.Acls), len(tt.setting.Acls))
			}
		})
	}
}

// Test edge cases for scan configuration
func TestScansConfigure_EdgeCases(t *testing.T) {
	t.Run("empty configuration", func(t *testing.T) {
		request := &ScansConfigureRequest{
			Settings: &ScansConfigureSetting{},
		}

		// Verify the request can be marshaled/unmarshaled
		data, err := sonic.Marshal(request)
		if err != nil {
			t.Errorf("Failed to marshal empty configuration: %v", err)
		}

		var unmarshaled ScansConfigureRequest
		err = sonic.Unmarshal(data, &unmarshaled)
		if err != nil {
			t.Errorf("Failed to unmarshal empty configuration: %v", err)
		}
	})

	t.Run("large configuration", func(t *testing.T) {
		// Create large arrays for testing
		var largeTargetGroups []string
		var largeAgentGroups []string
		var largeTextTargets []string
		var largeFileTargets []string
		var largeAcls []*PermissionResource

		for i := 0; i < 100; i++ {
			largeTargetGroups = append(largeTargetGroups, fmt.Sprintf("TargetGroup%d", i))
			largeAgentGroups = append(largeAgentGroups, fmt.Sprintf("AgentGroup%d", i))
			largeTextTargets = append(largeTextTargets, fmt.Sprintf("192.168.%d.1", i))
			largeFileTargets = append(largeFileTargets, fmt.Sprintf("targets%d.txt", i))
			largeAcls = append(largeAcls, &PermissionResource{
				Type:        "user",
				Permissions: 32,
				ID:          1000 + i,
			})
		}

		request := &ScansConfigureRequest{
			UUID: "large-configuration-uuid-with-very-long-string-for-testing-purposes-and-edge-cases",
			Settings: &ScansConfigureSetting{
				Name:         "Large Configuration Test with Very Long Name for Edge Case Testing",
				Description:  "Very long description that tests the limits of the configuration system and ensures that large amounts of text can be properly handled by the marshaling and unmarshaling processes without causing errors or data corruption",
				PolicyID:     999999,
				FolderID:     888888,
				ScannerID:    777777,
				Enabled:      true,
				Launch:       "RECURRING",
				Starttime:    "20241201T235959",
				Rrules:       "FREQ=DAILY;INTERVAL=1;BYHOUR=0,6,12,18;BYMINUTE=0,15,30,45",
				Timezone:     "America/New_York",
				TargetGroups: largeTargetGroups,
				AgentGroups:  largeAgentGroups,
				TextTargets:  largeTextTargets,
				FileTargets:  largeFileTargets,
				Emails:       "admin@example.com,user1@example.com,user2@example.com,user3@example.com,user4@example.com,user5@example.com",
				Acls:         largeAcls,
			},
		}

		// Verify the request can be marshaled/unmarshaled
		data, err := sonic.Marshal(request)
		if err != nil {
			t.Errorf("Failed to marshal large configuration: %v", err)
		}

		var unmarshaled ScansConfigureRequest
		err = sonic.Unmarshal(data, &unmarshaled)
		if err != nil {
			t.Errorf("Failed to unmarshal large configuration: %v", err)
		}

		// Verify array lengths
		if len(unmarshaled.Settings.TargetGroups) != 100 {
			t.Errorf("Expected 100 target groups, got %d", len(unmarshaled.Settings.TargetGroups))
		}
		if len(unmarshaled.Settings.AgentGroups) != 100 {
			t.Errorf("Expected 100 agent groups, got %d", len(unmarshaled.Settings.AgentGroups))
		}
		if len(unmarshaled.Settings.TextTargets) != 100 {
			t.Errorf("Expected 100 text targets, got %d", len(unmarshaled.Settings.TextTargets))
		}
	})

	t.Run("special characters in configuration", func(t *testing.T) {
		request := &ScansConfigureRequest{
			UUID: "special-chars-测试-🔒-uuid",
			Settings: &ScansConfigureSetting{
				Name:        "Special Characters Test: 測試 🔒 «»‹› ñáéíóú",
				Description: "Test with special characters: #$%^&*(){}[]|\\:;\"'<>,.?/~`+=_-",
				TextTargets: []string{"192.168.1.1"},
				Emails:      "test+special@example.com,user.name@sub-domain.example.org",
			},
		}

		// Verify the request can be marshaled/unmarshaled
		data, err := sonic.Marshal(request)
		if err != nil {
			t.Errorf("Failed to marshal special characters configuration: %v", err)
		}

		var unmarshaled ScansConfigureRequest
		err = sonic.Unmarshal(data, &unmarshaled)
		if err != nil {
			t.Errorf("Failed to unmarshal special characters configuration: %v", err)
		}

		if unmarshaled.Settings.Name != request.Settings.Name {
			t.Errorf("Special characters in name not preserved: got %s, want %s", unmarshaled.Settings.Name, request.Settings.Name)
		}
	})

	t.Run("minimal valid configuration", func(t *testing.T) {
		request := &ScansConfigureRequest{
			UUID: "min",
			Settings: &ScansConfigureSetting{
				Name:        "M",
				TextTargets: []string{"1.1.1.1"},
			},
		}

		// Verify the request can be marshaled/unmarshaled
		data, err := sonic.Marshal(request)
		if err != nil {
			t.Errorf("Failed to marshal minimal configuration: %v", err)
		}

		var unmarshaled ScansConfigureRequest
		err = sonic.Unmarshal(data, &unmarshaled)
		if err != nil {
			t.Errorf("Failed to unmarshal minimal configuration: %v", err)
		}
	})
}

func TestScansConfigureResponseValidation(t *testing.T) {
	// Test the response structure
	response := &ScansConfigureResponse{
		CreationDate:           1640995200,
		CustomTargets:          "192.168.1.1,10.0.0.1",
		DefaultPermissions:     64,
		Description:            "Test scan configuration response",
		Emails:                 "admin@example.com,user@example.com",
		ID:                     12345,
		LastModificationDate:   1640995800,
		Name:                   "Test Configured Scan",
		NotificationFilters:    "all",
		NotificationFilterType: "default",
		Owner:                  "admin",
		OwnerID:                1,
		PolicyID:               10,
		Rrules:                 "FREQ=WEEKLY;INTERVAL=1;BYDAY=MO",
		Shared:                 1,
		Starttime:              "20240101T120000",
		TagID:                  5,
		Timezone:               "UTC",
		Type:                   "public",
		UserPermissions:        128,
		UUID:                   "response-test-uuid",
	}

	// Test marshaling
	data, err := sonic.Marshal(response)
	if err != nil {
		t.Errorf("Failed to marshal response: %v", err)
		return
	}

	// Test unmarshaling
	var unmarshaled ScansConfigureResponse
	err = sonic.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
		return
	}

	// Verify key fields
	if unmarshaled.Name != "Test Configured Scan" {
		t.Errorf("Expected name 'Test Configured Scan', got '%s'", unmarshaled.Name)
	}
	if unmarshaled.ID != 12345 {
		t.Errorf("Expected ID 12345, got %d", unmarshaled.ID)
	}
	if unmarshaled.UUID != "response-test-uuid" {
		t.Errorf("Expected UUID 'response-test-uuid', got '%s'", unmarshaled.UUID)
	}
	if unmarshaled.PolicyID != 10 {
		t.Errorf("Expected PolicyID 10, got %d", unmarshaled.PolicyID)
	}
}

func TestScansConfigure_AuthenticationMethods(t *testing.T) {
	baseRequest := &ScansConfigureRequest{
		UUID: "auth-test-uuid",
		Settings: &ScansConfigureSetting{
			Name:        "Authentication Test",
			TextTargets: []string{"127.0.0.1"},
		},
	}

	tests := []struct {
		name        string
		options     []Option
		expectError bool
		description string
	}{
		{
			name: "valid API key authentication",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"valid-access-key-1234567890abcdef1234567890abcdef12345678",
					"valid-secret-key-1234567890abcdef1234567890abcdef12345678",
				),
			},
			expectError: false,
			description: "Should succeed with valid API keys",
		},
		{
			name: "valid session token authentication",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("valid-session-token-1234567890abcdef"),
			},
			expectError: false,
			description: "Should succeed with valid session token",
		},
		{
			name: "invalid API key authentication",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey("invalid", "keys"),
			},
			expectError: true,
			description: "Should fail with invalid API keys",
		},
		{
			name: "empty API key authentication",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey("", ""),
			},
			expectError: true,
			description: "Should fail with empty API keys",
		},
		{
			name: "invalid session token authentication",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("invalid-token"),
			},
			expectError: true,
			description: "Should fail with invalid session token",
		},
		{
			name: "empty session token authentication",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken(""),
			},
			expectError: true,
			description: "Should fail with empty session token",
		},
		{
			name: "no authentication",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
			},
			expectError: true,
			description: "Should fail with no authentication",
		},
		{
			name: "mixed authentication methods",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey("access-key", "secret-key"),
				WithToken("session-token"),
			},
			expectError: false,
			description: "Should use API key when both are provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(tt.options...)
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			_, err = c.ScansConfigure(1, baseRequest)
			if (err != nil) != tt.expectError {
				t.Errorf("ScansConfigure() error = %v, expectError %v - %s", err, tt.expectError, tt.description)
			}
		})
	}
}

func TestScansConfigure_SecurityTests(t *testing.T) {
	tests := []struct {
		name        string
		scanID      int
		request     *ScansConfigureRequest
		description string
	}{
		{
			name:   "scan ID boundary test - max int",
			scanID: 2147483647, // max int32
			request: &ScansConfigureRequest{
				UUID: "boundary-test-uuid",
				Settings: &ScansConfigureSetting{
					Name:        "Boundary Test",
					TextTargets: []string{"192.168.1.1"},
				},
			},
			description: "Test with maximum integer scan ID",
		},
		{
			name:   "large scan ID",
			scanID: 999999999,
			request: &ScansConfigureRequest{
				UUID: "large-id-test-uuid",
				Settings: &ScansConfigureSetting{
					Name:        "Large ID Test",
					TextTargets: []string{"10.0.0.1"},
				},
			},
			description: "Test with very large scan ID",
		},
		{
			name:   "injection attempt in UUID",
			scanID: 1,
			request: &ScansConfigureRequest{
				UUID: "'; DROP TABLE scans; --",
				Settings: &ScansConfigureSetting{
					Name:        "Injection Test",
					TextTargets: []string{"127.0.0.1"},
				},
			},
			description: "Test SQL injection attempt in UUID field",
		},
		{
			name:   "injection attempt in name",
			scanID: 1,
			request: &ScansConfigureRequest{
				UUID: "injection-name-test",
				Settings: &ScansConfigureSetting{
					Name:        "<script>alert('xss')</script>",
					Description: "../../etc/passwd",
					TextTargets: []string{"192.168.1.1"},
				},
			},
			description: "Test XSS and path traversal in name/description",
		},
		{
			name:   "malicious targets",
			scanID: 1,
			request: &ScansConfigureRequest{
				UUID: "malicious-targets-test",
				Settings: &ScansConfigureSetting{
					Name:        "Malicious Targets Test",
					TextTargets: []string{"../../../etc/passwd", "$(rm -rf /)", "0.0.0.0/0"},
				},
			},
			description: "Test with potentially malicious target specifications",
		},
		{
			name:   "malicious email addresses",
			scanID: 1,
			request: &ScansConfigureRequest{
				UUID: "malicious-email-test",
				Settings: &ScansConfigureSetting{
					Name:        "Email Test",
					Emails:      "test@example.com\r\nBcc: hacker@malicious.com",
					TextTargets: []string{"127.0.0.1"},
				},
			},
			description: "Test email header injection attempt",
		},
	}

	// These tests verify that the data structures can handle potentially malicious input
	// without crashing. Server-side validation should handle security concerns.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that potentially malicious input can be marshaled/unmarshaled safely
			data, err := sonic.Marshal(tt.request)
			if err != nil {
				t.Errorf("Failed to marshal potentially malicious request: %v", err)
				return
			}

			var unmarshaled ScansConfigureRequest
			err = sonic.Unmarshal(data, &unmarshaled)
			if err != nil {
				t.Errorf("Failed to unmarshal potentially malicious request: %v", err)
				return
			}

			// Verify that the data is preserved as-is (security validation happens server-side)
			if unmarshaled.UUID != tt.request.UUID {
				t.Errorf("UUID not preserved: got %s, want %s", unmarshaled.UUID, tt.request.UUID)
			}
		})
	}
}

func TestScansConfigure_ParameterValidation(t *testing.T) {
	// Test various parameter combinations and edge cases
	tests := []struct {
		name     string
		settings *ScansConfigureSetting
		valid    bool
	}{
		{
			name: "valid launch types",
			settings: &ScansConfigureSetting{
				Name:        "Launch Type Test",
				Launch:      "ONETIME",
				TextTargets: []string{"192.168.1.1"},
			},
			valid: true,
		},
		{
			name: "valid recurring launch",
			settings: &ScansConfigureSetting{
				Name:        "Recurring Test",
				Launch:      "RECURRING",
				Starttime:   "20240101T120000",
				Rrules:      "FREQ=DAILY;INTERVAL=1",
				TextTargets: []string{"10.0.0.1"},
			},
			valid: true,
		},
		{
			name: "timezone validation",
			settings: &ScansConfigureSetting{
				Name:        "Timezone Test",
				Timezone:    "America/New_York",
				TextTargets: []string{"172.16.0.1"},
			},
			valid: true,
		},
		{
			name: "invalid timezone format",
			settings: &ScansConfigureSetting{
				Name:        "Invalid Timezone Test",
				Timezone:    "Invalid/Timezone",
				TextTargets: []string{"192.168.1.1"},
			},
			valid: true, // Client-side allows any string, server validates
		},
		{
			name: "policy ID validation",
			settings: &ScansConfigureSetting{
				Name:        "Policy ID Test",
				PolicyID:    -1, // Negative policy ID
				TextTargets: []string{"10.0.0.1"},
			},
			valid: true, // Client allows, server validates
		},
		{
			name: "folder ID validation",
			settings: &ScansConfigureSetting{
				Name:        "Folder ID Test",
				FolderID:    0, // Zero folder ID
				TextTargets: []string{"172.16.0.1"},
			},
			valid: true,
		},
		{
			name: "scanner ID validation",
			settings: &ScansConfigureSetting{
				Name:        "Scanner ID Test",
				ScannerID:   999999, // Very large scanner ID
				TextTargets: []string{"192.168.1.1"},
			},
			valid: true,
		},
		{
			name: "empty target arrays",
			settings: &ScansConfigureSetting{
				Name:         "Empty Arrays Test",
				TargetGroups: []string{},
				AgentGroups:  []string{},
				TextTargets:  []string{},
				FileTargets:  []string{},
			},
			valid: true,
		},
		{
			name: "nil target arrays",
			settings: &ScansConfigureSetting{
				Name:         "Nil Arrays Test",
				TargetGroups: nil,
				AgentGroups:  nil,
				TextTargets:  nil,
				FileTargets:  nil,
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := &ScansConfigureRequest{
				UUID:     "param-validation-test",
				Settings: tt.settings,
			}

			data, err := sonic.Marshal(request)
			if err != nil && tt.valid {
				t.Errorf("Expected valid configuration, but marshaling failed: %v", err)
				return
			}
			if err == nil && !tt.valid {
				t.Errorf("Expected invalid configuration, but marshaling succeeded")
				return
			}

			if tt.valid {
				var unmarshaled ScansConfigureRequest
				err = sonic.Unmarshal(data, &unmarshaled)
				if err != nil {
					t.Errorf("Failed to unmarshal valid configuration: %v", err)
				}
			}
		})
	}
}
