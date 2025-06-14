# TGMG - Telegram Bot Manager

A command-line tool for managing multiple Telegram bots and their webhooks.

## Overview

TGMG allows you to manage multiple Telegram bots through a simple CLI interface. It provides commands for:

- Listing all configured bots
- Managing webhooks (setting, deleting, and viewing information)

## Installation

### From Source

```bash
git clone https://github.com/tutunak/tgmg.git
cd tgmg
go install
```

## Configuration

TGMG looks for bot tokens in environment variables with the following pattern:

- `TGMG_BOT_TOKEN` - Main bot (ID: "main")
- `TGMG_BOT_TOKEN_NAME` - Additional bots (ID: "name" in lowercase)

Example:
```bash
export TGMG_BOT_TOKEN="123456789:ABCDEFghijklmnopQRSTUVwxyz"
export TGMG_BOT_TOKEN_TEST="987654321:ZYXWVUTsrqponmlkJIHGFEDcba"
```

## Usage

### Listing Configured Bots

```bash
tgmg list
```

This will display all configured bots with their IDs.

### Managing Webhooks

#### Setting a Webhook

```bash
tgmg webhook set [bot-id] --url https://your-webhook-url.com
```

Options:
- `--url` (required): HTTPS URL to send updates to
- `--ip-address`: Fixed IP address for webhook requests
- `--max-connections`: Maximum simultaneous HTTPS connections (1-100)
- `--allowed-updates`: List of update types to receive
- `--drop-pending`: Drop all pending updates
- `--secret-token`: Secret token for webhook validation

#### Deleting a Webhook

```bash
tgmg webhook delete [bot-id]
```

Options:
- `--drop-pending`: Drop all pending updates

#### Getting Webhook Information

```bash
tgmg webhook info [bot-id]
```

This displays detailed information about the configured webhook.

## Examples

### Setting up a webhook for the main bot

```bash
tgmg webhook set --url https://example.com/webhook
```

### Setting up a webhook for a specific bot

```bash
tgmg webhook set test --url https://example.com/webhook --max-connections 50
```

### Getting webhook information

```bash
tgmg webhook info test
```

## Notes

- All webhook URLs must use HTTPS
- The tool requires valid Telegram bot tokens to be set as environment variables
- If you have only one bot configured, you can omit the bot-id in commands

## Requirements

- Go 1.23.4 or higher
- Valid Telegram bot token(s)

## Dependencies

- [github.com/spf13/cobra](https://github.com/spf13/cobra) - Command line interface library
