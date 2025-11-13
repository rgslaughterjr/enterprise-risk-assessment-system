# GitHub MCP Server Setup

This project has been configured with the GitHub MCP (Model Context Protocol) server, which allows Claude Code to interact with GitHub repositories, issues, pull requests, and more.

## Configuration Files

### `.env`
Contains the GitHub Personal Access Token:
```
GITHUB_PAT=your_token_here
```
**Note**: This file is git-ignored for security.

### `.mcp.json`
Configures the GitHub MCP server for this project:
```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "..."
      }
    }
  }
}
```
**Note**: This file is git-ignored (covered by `*.json` pattern) to protect the token.

### Claude Settings
The Claude Code settings at `~/.claude/settings.json` has been updated with:
```json
"enableAllProjectMcpServers": true
```

This automatically approves all MCP servers defined in this project's `.mcp.json`.

## Capabilities

With the GitHub MCP server, Claude Code can now:

- **Repository Management**: Browse and query code, search files, analyze commits
- **Issue & PR Operations**: Create, update, and manage issues and pull requests
- **Workflow Intelligence**: Monitor GitHub Actions, analyze build failures
- **Code Analysis**: Examine security findings, review Dependabot alerts
- **Team Collaboration**: Access discussions, manage notifications

## Restart Required

**Important**: You may need to restart your Claude Code session for the MCP server to be fully loaded and available.

## Token Permissions

The GitHub Personal Access Token has the following scopes:
- `repo` - Full control of private repositories
- `workflow` - Update GitHub Actions workflows
- `read:org` - Read organization membership

## Security Notes

- The `.env` and `.mcp.json` files contain sensitive credentials and are git-ignored
- Never commit these files to version control
- Regenerate tokens if they are accidentally exposed
- Follow principle of least privilege when granting token scopes

## References

- [GitHub MCP Server Documentation](https://github.com/github/github-mcp-server)
- [Installation Guide](https://github.com/github/github-mcp-server/blob/main/docs/installation-guides/install-claude.md)
