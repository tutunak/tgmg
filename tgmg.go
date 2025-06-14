package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

type BotConfig struct {
	ID    string
	Token string
	Name  string
}

type TelegramManager struct {
	Bots []BotConfig
}

// WebhookInfo represents the response from getWebhookInfo
type WebhookInfo struct {
	URL                          string   `json:"url"`
	HasCustomCertificate         bool     `json:"has_custom_certificate"`
	PendingUpdateCount           int      `json:"pending_update_count"`
	IPAddress                    string   `json:"ip_address,omitempty"`
	LastErrorDate                int64    `json:"last_error_date,omitempty"`
	LastErrorMessage             string   `json:"last_error_message,omitempty"`
	LastSynchronizationErrorDate int64    `json:"last_synchronization_error_date,omitempty"`
	MaxConnections               int      `json:"max_connections,omitempty"`
	AllowedUpdates               []string `json:"allowed_updates,omitempty"`
}

type TelegramResponse struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result,omitempty"`
	Description string          `json:"description,omitempty"`
}

func NewTelegramManager() *TelegramManager {
	tm := &TelegramManager{}
	tm.loadBotTokens()
	return tm
}

func (tm *TelegramManager) loadBotTokens() {
	tokenPattern := regexp.MustCompile(`^TGMG_BOT_TOKEN(_.+)?$`)

	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key, value := parts[0], parts[1]
		if tokenPattern.MatchString(key) && value != "" {
			botConfig := BotConfig{
				Token: value,
				Name:  key,
			}

			if key == "TGMG_BOT_TOKEN" {
				botConfig.ID = "main"
			} else {
				suffix := strings.TrimPrefix(key, "TGMG_BOT_TOKEN_")
				botConfig.ID = strings.ToLower(suffix)
			}

			tm.Bots = append(tm.Bots, botConfig)
		}
	}

	// Sort bots by ID for consistent ordering
	sort.Slice(tm.Bots, func(i, j int) bool {
		return tm.Bots[i].ID < tm.Bots[j].ID
	})
}

func (tm *TelegramManager) getBotByID(id string) (*BotConfig, error) {
	if len(tm.Bots) == 0 {
		return nil, fmt.Errorf("no bot tokens found")
	}

	if len(tm.Bots) == 1 && id == "" {
		return &tm.Bots[0], nil
	}

	if id == "" {
		return nil, fmt.Errorf("bot ID is required when multiple bots are configured")
	}

	for _, bot := range tm.Bots {
		if bot.ID == id {
			return &bot, nil
		}
	}

	return nil, fmt.Errorf("bot with ID '%s' not found", id)
}

func (tm *TelegramManager) makeAPIRequest(token, method string, payload map[string]interface{}) (*TelegramResponse, error) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/%s", token, method)

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("Error closing response body: %v\n", err)
		}
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	var telegramResp TelegramResponse
	if err := json.Unmarshal(body, &telegramResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &telegramResp, nil
}

func main() {
	tm := NewTelegramManager()

	var rootCmd = &cobra.Command{
		Use:   "tgmg",
		Short: "Telegram Bot Manager - A CLI tool for managing Telegram bots",
		Long:  "A command-line tool for managing multiple Telegram bots and their webhooks",
	}

	// List bots command
	var listCmd = &cobra.Command{
		Use:   "list",
		Short: "List all configured bot IDs",
		Run: func(cmd *cobra.Command, args []string) {
			if len(tm.Bots) == 0 {
				fmt.Println("No bot tokens found. Please set TGMG_BOT_TOKEN environment variables.")
				return
			}

			fmt.Printf("Found %d bot(s):\n", len(tm.Bots))
			for _, bot := range tm.Bots {
				fmt.Printf("  ID: %s (from %s)\n", bot.ID, bot.Name)
			}
		},
	}

	// Webhook management commands
	var webhookCmd = &cobra.Command{
		Use:   "webhook",
		Short: "Manage bot webhooks",
	}

	// Set webhook command
	var setWebhookCmd = &cobra.Command{
		Use:   "set [bot-id]",
		Short: "Set webhook for a bot",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			botID := ""
			if len(args) > 0 {
				botID = args[0]
			}

			bot, err := tm.getBotByID(botID)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				return
			}

			url, _ := cmd.Flags().GetString("url")
			if url == "" {
				fmt.Println("Error: --url is required")
				return
			}

			payload := map[string]interface{}{
				"url": url,
			}

			// Add optional parameters
			if ipAddress, _ := cmd.Flags().GetString("ip-address"); ipAddress != "" {
				payload["ip_address"] = ipAddress
			}
			if maxConn, _ := cmd.Flags().GetInt("max-connections"); maxConn > 0 {
				payload["max_connections"] = maxConn
			}
			if allowedUpdates, _ := cmd.Flags().GetStringSlice("allowed-updates"); len(allowedUpdates) > 0 {
				payload["allowed_updates"] = allowedUpdates
			}
			if dropPending, _ := cmd.Flags().GetBool("drop-pending"); dropPending {
				payload["drop_pending_updates"] = true
			}
			if secretToken, _ := cmd.Flags().GetString("secret-token"); secretToken != "" {
				payload["secret_token"] = secretToken
			}

			resp, err := tm.makeAPIRequest(bot.Token, "setWebhook", payload)
			if err != nil {
				fmt.Printf("Error making request: %v\n", err)
				return
			}

			if resp.OK {
				fmt.Printf("✅ Webhook set successfully for bot '%s'\n", bot.ID)
			} else {
				fmt.Printf("❌ Failed to set webhook: %s\n", resp.Description)
			}
		},
	}

	setWebhookCmd.Flags().String("url", "", "HTTPS URL to send updates to (required)")
	setWebhookCmd.Flags().String("ip-address", "", "Fixed IP address for webhook requests")
	setWebhookCmd.Flags().Int("max-connections", 0, "Maximum simultaneous HTTPS connections (1-100)")
	setWebhookCmd.Flags().StringSlice("allowed-updates", []string{}, "List of update types to receive")
	setWebhookCmd.Flags().Bool("drop-pending", false, "Drop all pending updates")
	setWebhookCmd.Flags().String("secret-token", "", "Secret token for webhook validation")

	// Delete webhook command
	var deleteWebhookCmd = &cobra.Command{
		Use:   "delete [bot-id]",
		Short: "Delete webhook for a bot",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			botID := ""
			if len(args) > 0 {
				botID = args[0]
			}

			bot, err := tm.getBotByID(botID)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				return
			}

			payload := map[string]interface{}{}
			if dropPending, _ := cmd.Flags().GetBool("drop-pending"); dropPending {
				payload["drop_pending_updates"] = true
			}

			resp, err := tm.makeAPIRequest(bot.Token, "deleteWebhook", payload)
			if err != nil {
				fmt.Printf("Error making request: %v\n", err)
				return
			}

			if resp.OK {
				fmt.Printf("✅ Webhook deleted successfully for bot '%s'\n", bot.ID)
			} else {
				fmt.Printf("❌ Failed to delete webhook: %s\n", resp.Description)
			}
		},
	}

	deleteWebhookCmd.Flags().Bool("drop-pending", false, "Drop all pending updates")

	// Get webhook info command
	var getWebhookCmd = &cobra.Command{
		Use:   "info [bot-id]",
		Short: "Get webhook information for a bot",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			botID := ""
			if len(args) > 0 {
				botID = args[0]
			}

			bot, err := tm.getBotByID(botID)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				return
			}

			resp, err := tm.makeAPIRequest(bot.Token, "getWebhookInfo", map[string]interface{}{})
			if err != nil {
				fmt.Printf("Error making request: %v\n", err)
				return
			}

			if !resp.OK {
				fmt.Printf("❌ Failed to get webhook info: %s\n", resp.Description)
				return
			}

			var webhookInfo WebhookInfo
			if err := json.Unmarshal(resp.Result, &webhookInfo); err != nil {
				fmt.Printf("Error parsing webhook info: %v\n", err)
				return
			}

			fmt.Printf("📋 Webhook Info for bot '%s':\n", bot.ID)
			fmt.Printf("  URL: %s\n", webhookInfo.URL)
			fmt.Printf("  Has Custom Certificate: %t\n", webhookInfo.HasCustomCertificate)
			fmt.Printf("  Pending Updates: %d\n", webhookInfo.PendingUpdateCount)

			if webhookInfo.IPAddress != "" {
				fmt.Printf("  IP Address: %s\n", webhookInfo.IPAddress)
			}
			if webhookInfo.MaxConnections > 0 {
				fmt.Printf("  Max Connections: %d\n", webhookInfo.MaxConnections)
			}
			if len(webhookInfo.AllowedUpdates) > 0 {
				fmt.Printf("  Allowed Updates: %s\n", strings.Join(webhookInfo.AllowedUpdates, ", "))
			}
			if webhookInfo.LastErrorDate > 0 {
				fmt.Printf("  Last Error Date: %d\n", webhookInfo.LastErrorDate)
				fmt.Printf("  Last Error Message: %s\n", webhookInfo.LastErrorMessage)
			}
		},
	}

	// Add commands to webhook group
	webhookCmd.AddCommand(setWebhookCmd, deleteWebhookCmd, getWebhookCmd)

	// Add commands to root
	rootCmd.AddCommand(listCmd, webhookCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
