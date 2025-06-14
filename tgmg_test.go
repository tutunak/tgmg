package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// Test helper to backup and restore environment
func backupEnv() map[string]string {
	backup := make(map[string]string)
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			backup[parts[0]] = parts[1]
		}
	}
	return backup
}

func restoreEnv(backup map[string]string) {
	os.Clearenv()
	for key, value := range backup {
		os.Setenv(key, value)
	}
}

// Mock HTTP server with configurable responses
func setupMockServer(responses map[string]mockResponse) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		method := strings.TrimPrefix(path, "/bot")
		if idx := strings.Index(method, "/"); idx != -1 {
			method = method[idx+1:]
		}

		if response, exists := responses[method]; exists {
			w.WriteHeader(response.StatusCode)
			fmt.Fprint(w, response.Body)
		} else {
			w.WriteHeader(404)
			fmt.Fprint(w, `{"ok":false,"description":"Method not found"}`)
		}
	}))
}

type mockResponse struct {
	StatusCode int
	Body       string
}

// Test bot token loading from environment variables
func TestLoadBotTokens(t *testing.T) {
	envBackup := backupEnv()
	defer restoreEnv(envBackup)

	tests := []struct {
		name     string
		envVars  map[string]string
		expected []BotConfig
	}{
		{
			name:     "No environment variables",
			envVars:  map[string]string{},
			expected: []BotConfig{},
		},
		{
			name: "Single main token",
			envVars: map[string]string{
				"TGMG_BOT_TOKEN": "main_token_123",
			},
			expected: []BotConfig{
				{ID: "main", Token: "main_token_123", Name: "TGMG_BOT_TOKEN"},
			},
		},
		{
			name: "Multiple tokens with different suffixes",
			envVars: map[string]string{
				"TGMG_BOT_TOKEN":      "main_token",
				"TGMG_BOT_TOKEN_DEV":  "dev_token",
				"TGMG_BOT_TOKEN_PROD": "prod_token",
				"TGMG_BOT_TOKEN_123":  "numeric_token",
			},
			expected: []BotConfig{
				{ID: "123", Token: "numeric_token", Name: "TGMG_BOT_TOKEN_123"},
				{ID: "dev", Token: "dev_token", Name: "TGMG_BOT_TOKEN_DEV"},
				{ID: "main", Token: "main_token", Name: "TGMG_BOT_TOKEN"},
				{ID: "prod", Token: "prod_token", Name: "TGMG_BOT_TOKEN_PROD"},
			},
		},
		{
			name: "Empty token values ignored",
			envVars: map[string]string{
				"TGMG_BOT_TOKEN":     "valid_token",
				"TGMG_BOT_TOKEN_DEV": "",
				"TGMG_BOT_TOKEN_":    "empty_suffix",
			},
			expected: []BotConfig{
				{ID: "", Token: "empty_suffix", Name: "TGMG_BOT_TOKEN_"},
				{ID: "main", Token: "valid_token", Name: "TGMG_BOT_TOKEN"},
			},
		},
		{
			name: "Special characters in suffix",
			envVars: map[string]string{
				"TGMG_BOT_TOKEN_SPECIAL-CHARS_123": "special_token",
				"TGMG_BOT_TOKEN_under_score":       "underscore_token",
			},
			expected: []BotConfig{
				{ID: "special-chars_123", Token: "special_token", Name: "TGMG_BOT_TOKEN_SPECIAL-CHARS_123"},
				{ID: "under_score", Token: "underscore_token", Name: "TGMG_BOT_TOKEN_under_score"},
			},
		},
		{
			name: "Irrelevant environment variables ignored",
			envVars: map[string]string{
				"TGMG_BOT_TOKEN":  "valid_token",
				"OTHER_BOT_TOKEN": "ignored",
				"TGMG_BOT_CONFIG": "ignored",
				"TG_BOT_TOKEN":    "ignored",
				"TELEGRAM_TOKEN":  "ignored",
			},
			expected: []BotConfig{
				{ID: "main", Token: "valid_token", Name: "TGMG_BOT_TOKEN"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Clearenv()
			for key, value := range tt.envVars {
				os.Setenv(key, value)
			}

			tm := NewTelegramManager()

			if len(tm.Bots) != len(tt.expected) {
				t.Errorf("Expected %d bots, got %d", len(tt.expected), len(tm.Bots))
			}

			for i, expected := range tt.expected {
				if i >= len(tm.Bots) {
					t.Errorf("Missing bot at index %d", i)
					continue
				}
				bot := tm.Bots[i]
				if bot.ID != expected.ID || bot.Token != expected.Token || bot.Name != expected.Name {
					t.Errorf("Bot %d: expected %+v, got %+v", i, expected, bot)
				}
			}
		})
	}
}

// Test getBotByID functionality
func TestGetBotByID(t *testing.T) {
	tests := []struct {
		name        string
		bots        []BotConfig
		id          string
		expectedBot *BotConfig
		expectError bool
		errorMsg    string
	}{
		{
			name:        "No bots configured",
			bots:        []BotConfig{},
			id:          "",
			expectedBot: nil,
			expectError: true,
			errorMsg:    "no bot tokens found",
		},
		{
			name: "Single bot with empty ID",
			bots: []BotConfig{
				{ID: "main", Token: "token123"},
			},
			id:          "",
			expectedBot: &BotConfig{ID: "main", Token: "token123"},
			expectError: false,
		},
		{
			name: "Single bot with matching ID",
			bots: []BotConfig{
				{ID: "main", Token: "token123"},
			},
			id:          "main",
			expectedBot: &BotConfig{ID: "main", Token: "token123"},
			expectError: false,
		},
		{
			name: "Multiple bots with empty ID should error",
			bots: []BotConfig{
				{ID: "main", Token: "token1"},
				{ID: "dev", Token: "token2"},
			},
			id:          "",
			expectedBot: nil,
			expectError: true,
			errorMsg:    "bot ID is required when multiple bots are configured",
		},
		{
			name: "Multiple bots with valid ID",
			bots: []BotConfig{
				{ID: "main", Token: "token1"},
				{ID: "dev", Token: "token2"},
			},
			id:          "dev",
			expectedBot: &BotConfig{ID: "dev", Token: "token2"},
			expectError: false,
		},
		{
			name: "Unknown bot ID",
			bots: []BotConfig{
				{ID: "main", Token: "token1"},
			},
			id:          "unknown",
			expectedBot: nil,
			expectError: true,
			errorMsg:    "bot with ID 'unknown' not found",
		},
		{
			name: "Case sensitive ID matching",
			bots: []BotConfig{
				{ID: "main", Token: "token1"},
			},
			id:          "MAIN",
			expectedBot: nil,
			expectError: true,
			errorMsg:    "bot with ID 'MAIN' not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tm := &TelegramManager{Bots: tt.bots}

			bot, err := tm.getBotByID(tt.id)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if !reflect.DeepEqual(bot, tt.expectedBot) {
					t.Errorf("Expected bot %+v, got %+v", tt.expectedBot, bot)
				}
			}
		})
	}
}

// Test API request functionality
func TestMakeAPIRequest(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		payload       map[string]interface{}
		mockResponses map[string]mockResponse
		expectedOK    bool
		expectedError string
	}{
		{
			name:    "Successful API call",
			method:  "getWebhookInfo",
			payload: map[string]interface{}{},
			mockResponses: map[string]mockResponse{
				"getWebhookInfo": {200, `{"ok":true,"result":{"url":"https://example.com"}}`},
			},
			expectedOK: true,
		},
		{
			name:    "API error response",
			method:  "setWebhook",
			payload: map[string]interface{}{"url": "invalid"},
			mockResponses: map[string]mockResponse{
				"setWebhook": {400, `{"ok":false,"description":"Bad Request: invalid webhook URL"}`},
			},
			expectedOK: false,
		},
		{
			name:    "Network error simulation",
			method:  "getWebhookInfo",
			payload: map[string]interface{}{},
			mockResponses: map[string]mockResponse{
				"getWebhookInfo": {500, `Internal Server Error`},
			},
			expectedError: "failed to parse response",
		},
		{
			name:    "Invalid JSON response",
			method:  "getWebhookInfo",
			payload: map[string]interface{}{},
			mockResponses: map[string]mockResponse{
				"getWebhookInfo": {200, `{"ok":true,"result":invalid json}`},
			},
			expectedError: "failed to parse response",
		},
		{
			name:    "Empty response",
			method:  "getWebhookInfo",
			payload: map[string]interface{}{},
			mockResponses: map[string]mockResponse{
				"getWebhookInfo": {200, ``},
			},
			expectedError: "failed to parse response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := setupMockServer(tt.mockResponses)
			defer server.Close()

			tm := NewTelegramManager()

			// Replace the base URL for testing
			originalURL := "https://api.telegram.org"
			testURL := server.URL

			resp, err := tm.makeAPIRequestWithURL(testURL+"/bot%s/%s", "test_token", tt.method, tt.payload)

			if tt.expectedError != "" {
				if err == nil {
					t.Errorf("Expected error containing '%s', got none", tt.expectedError)
				} else if !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if resp.OK != tt.expectedOK {
					t.Errorf("Expected OK=%t, got OK=%t", tt.expectedOK, resp.OK)
				}
			}

			_ = originalURL // Avoid unused variable
		})
	}
}

// Test webhook info JSON parsing
func TestWebhookInfoParsing(t *testing.T) {
	tests := []struct {
		name        string
		jsonData    string
		expected    WebhookInfo
		expectError bool
	}{
		{
			name:     "Complete webhook info",
			jsonData: `{"url":"https://example.com/webhook","has_custom_certificate":true,"pending_update_count":5,"ip_address":"192.168.1.1","last_error_date":1234567890,"last_error_message":"Connection timeout","max_connections":100,"allowed_updates":["message","callback_query"]}`,
			expected: WebhookInfo{
				URL:                  "https://example.com/webhook",
				HasCustomCertificate: true,
				PendingUpdateCount:   5,
				IPAddress:            "192.168.1.1",
				LastErrorDate:        1234567890,
				LastErrorMessage:     "Connection timeout",
				MaxConnections:       100,
				AllowedUpdates:       []string{"message", "callback_query"},
			},
			expectError: false,
		},
		{
			name:     "Minimal webhook info",
			jsonData: `{"url":"","has_custom_certificate":false,"pending_update_count":0}`,
			expected: WebhookInfo{
				URL:                  "",
				HasCustomCertificate: false,
				PendingUpdateCount:   0,
			},
			expectError: false,
		},
		{
			name:        "Invalid JSON",
			jsonData:    `{"url":"https://example.com","invalid json}`,
			expected:    WebhookInfo{},
			expectError: true,
		},
		{
			name:     "Extra fields ignored",
			jsonData: `{"url":"https://example.com","has_custom_certificate":true,"pending_update_count":1,"extra_field":"ignored"}`,
			expected: WebhookInfo{
				URL:                  "https://example.com",
				HasCustomCertificate: true,
				PendingUpdateCount:   1,
			},
			expectError: false,
		},
		{
			name:     "Null values",
			jsonData: `{"url":"https://example.com","has_custom_certificate":null,"pending_update_count":0,"allowed_updates":null}`,
			expected: WebhookInfo{
				URL:                  "https://example.com",
				HasCustomCertificate: false,
				PendingUpdateCount:   0,
				AllowedUpdates:       nil,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var info WebhookInfo
			err := json.Unmarshal([]byte(tt.jsonData), &info)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if !reflect.DeepEqual(info, tt.expected) {
					t.Errorf("Expected %+v, got %+v", tt.expected, info)
				}
			}
		})
	}
}

// Test command flag validation
func TestCommandFlags(t *testing.T) {
	tests := []struct {
		name        string
		command     *cobra.Command
		flags       map[string]string
		expectError bool
	}{
		{
			name:    "setWebhook with valid URL",
			command: &cobra.Command{},
			flags: map[string]string{
				"url": "https://example.com/webhook",
			},
			expectError: false,
		},
		{
			name:    "setWebhook with empty URL",
			command: &cobra.Command{},
			flags: map[string]string{
				"url": "",
			},
			expectError: true,
		},
		{
			name:    "setWebhook with all optional parameters",
			command: &cobra.Command{},
			flags: map[string]string{
				"url":             "https://example.com/webhook",
				"ip-address":      "192.168.1.1",
				"max-connections": "50",
				"secret-token":    "secret123",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup command with flags similar to setWebhookCmd
			cmd := &cobra.Command{}
			cmd.Flags().String("url", "", "HTTPS URL to send updates to")
			cmd.Flags().String("ip-address", "", "Fixed IP address")
			cmd.Flags().Int("max-connections", 0, "Maximum connections")
			cmd.Flags().String("secret-token", "", "Secret token")

			// Set flags
			for key, value := range tt.flags {
				cmd.Flags().Set(key, value)
			}

			// Validate URL requirement
			url, _ := cmd.Flags().GetString("url")
			hasError := url == ""

			if tt.expectError != hasError {
				t.Errorf("Expected error=%t, got error=%t", tt.expectError, hasError)
			}
		})
	}
}

// Test concurrent access to TelegramManager
func TestConcurrentAccess(t *testing.T) {
	envBackup := backupEnv()
	defer restoreEnv(envBackup)

	os.Clearenv()
	os.Setenv("TGMG_BOT_TOKEN", "token1")
	os.Setenv("TGMG_BOT_TOKEN_DEV", "token2")

	tm := NewTelegramManager()

	done := make(chan bool, 10)

	// Launch multiple goroutines accessing the same TelegramManager
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- true }()

			if id%2 == 0 {
				bot, err := tm.getBotByID("main")
				if err != nil || bot.Token != "token1" {
					t.Errorf("Goroutine %d: expected main bot, got error: %v", id, err)
				}
			} else {
				bot, err := tm.getBotByID("dev")
				if err != nil || bot.Token != "token2" {
					t.Errorf("Goroutine %d: expected dev bot, got error: %v", id, err)
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("Timeout waiting for goroutines")
		}
	}
}

// Test edge cases for environment variable patterns
func TestEnvironmentVariableEdgeCases(t *testing.T) {
	envBackup := backupEnv()
	defer restoreEnv(envBackup)

	tests := []struct {
		name     string
		envVars  map[string]string
		expected int
	}{
		{
			name: "Variables with similar names",
			envVars: map[string]string{
				"TGMG_BOT_TOKEN":        "valid1",
				"TGMG_BOT_TOKEN_":       "valid2", // Empty suffix
				"TGMG_BOT_TOKEN_PREFIX": "valid3",
				"TGMG_BOT_TOKENS":       "invalid", // Extra 'S'
				"MY_TGMG_BOT_TOKEN":     "invalid", // Prefix
			},
			expected: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Clearenv()
			for key, value := range tt.envVars {
				os.Setenv(key, value)
			}

			tm := NewTelegramManager()
			if len(tm.Bots) != tt.expected {
				t.Errorf("Expected %d bots, got %d", tt.expected, len(tm.Bots))
			}
		})
	}
}

// Helper method for testing with custom URL
func (tm *TelegramManager) makeAPIRequestWithURL(urlFormat, token, method string, payload map[string]interface{}) (*TelegramResponse, error) {
	url := fmt.Sprintf(urlFormat, token, method)

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	resp, err := http.Post(url, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	body := make([]byte, 0, resp.ContentLength)
	buffer := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buffer)
		if n > 0 {
			body = append(body, buffer[:n]...)
		}
		if err != nil {
			break
		}
	}

	var telegramResp TelegramResponse
	if err := json.Unmarshal(body, &telegramResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &telegramResp, nil
}

// Benchmark tests
func BenchmarkLoadBotTokens(b *testing.B) {
	envBackup := backupEnv()
	defer restoreEnv(envBackup)

	os.Clearenv()
	for i := 0; i < 100; i++ {
		os.Setenv(fmt.Sprintf("TGMG_BOT_TOKEN_%d", i), fmt.Sprintf("token_%d", i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tm := NewTelegramManager()
		_ = tm.Bots
	}
}

func BenchmarkGetBotByID(b *testing.B) {
	bots := make([]BotConfig, 1000)
	for i := 0; i < 1000; i++ {
		bots[i] = BotConfig{
			ID:    fmt.Sprintf("bot_%d", i),
			Token: fmt.Sprintf("token_%d", i),
		}
	}

	tm := &TelegramManager{Bots: bots}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = tm.getBotByID("bot_500")
	}
}
