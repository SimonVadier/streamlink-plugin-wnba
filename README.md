# WNBA League Pass Streamlink Plugin

A Streamlink plugin that enables watching WNBA League Pass content through the Streamlink CLI.

## Description

This plugin allows you to stream video content from [WNBA League Pass](https://leaguepass.wnba.com/) using Streamlink. It supports both live games and video-on-demand content with proper authentication.

## Installation

1. Copy the [`leaguepass.py`](./leaguepass.py) file to your Streamlink plugins directory:
   - Windows: `%APPDATA%\streamlink\plugins\`
   - Linux/macOS: `~/.config/streamlink/plugins/`

## Usage

### Free Content

Some VOD and streams are available without authentication:

`streamlink "https://leaguepass.wnba.com/video/12345" best`

### Authenticated Content

For content requiring a WNBA League Pass subscription:

`streamlink --leaguepass-email YOUR_EMAIL --leaguepass-password YOUR_PASSWORD "https://leaguepass.wnba.com/live/12345" best`

### Parameters

| Parameter | Description |
|-----------|-------------|
| `--leaguepass-email` | Your WNBA League Pass account email (only required for subscription content) |
| `--leaguepass-password` | Your WNBA League Pass account password (only required for subscription content) |

## Supported URLs

- Live games: `https://leaguepass.wnba.com/live/{game_id}`
- Videos: `https://leaguepass.wnba.com/video/{video_id}`

## License

This project is licensed under the [Unlicense](./LICENSE) - see the LICENSE file for details.