# Claude Code Configuration

This directory contains Claude Code configuration and custom skills for this project.

## Structure

```
.claude/
├── README.md           # This file
└── skills/            # Project-scoped skills
    └── github-course-manager/
        └── SKILL.md   # GitHub MCP course management skill
```

## Skills

### GitHub Course Manager

**Location**: `.claude/skills/github-course-manager/`

A skill for managing your 12-week AI Agent Developer Course using GitHub MCP capabilities.

**How to Use**:
```
"Set up my AI Agent course repository"
"Create a Week 3 assignment on RAG systems"
"Show my course progress"
"Create a PR for my Week 5 assignment"
```

**Features**:
- Create weekly assignments as GitHub issues
- Track progress through milestones
- Manage branches and pull requests
- Organize course materials
- Generate progress reports

**Documentation**: See `docs/GITHUB_COURSE_MANAGER_SKILL.md` for complete usage guide.

## Scope

These are **project-scoped** skills, meaning:
- ✅ Available when working on this repository
- ✅ Version controlled and shared with collaborators
- ✅ Automatically loaded when opening this project
- ✅ Can be customized per-project

## User-Scoped Skills

In addition to project-scoped skills, you may have user-scoped skills at:
- `~/.claude/skills/` - Personal skills that apply to all your projects

## Prerequisites

For the GitHub Course Manager skill to work:
1. GitHub MCP server must be configured (see `GITHUB_MCP_SETUP.md`)
2. Claude Code session must be restarted after MCP installation
3. GitHub PAT must be valid with appropriate scopes

## Adding More Skills

To add additional project skills:

1. Create a new directory: `.claude/skills/your-skill-name/`
2. Add a `SKILL.md` file with frontmatter:
   ```markdown
   ---
   name: your-skill-name
   description: What this skill does and when to use it
   ---

   # Your Skill Name

   [Skill instructions here]
   ```
3. Commit and push to share with team

## References

- [Claude Code Skills Documentation](https://docs.claude.com)
- [GitHub MCP Server](https://github.com/github/github-mcp-server)
- Project Documentation: `docs/`
