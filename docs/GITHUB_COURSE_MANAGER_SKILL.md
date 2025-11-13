# GitHub Course Manager Skill

A Claude Code skill for managing your 12-week AI Agent Developer Course using GitHub MCP capabilities.

## Overview

This skill helps you organize and track your AI Agent Developer Course through GitHub by:
- Creating structured weekly assignments as GitHub issues
- Managing course branches and pull requests
- Tracking progress through milestones and labels
- Organizing course materials in a structured repository
- Generating progress reports

## Installation

The skill is installed at: `~/.claude/skills/github-course-manager/`

## Prerequisites

✅ GitHub MCP server must be configured (see `GITHUB_MCP_SETUP.md`)
✅ GitHub Personal Access Token with `repo`, `workflow`, `read:org` scopes
✅ Claude Code session restart required after MCP installation

## Usage

### How to Invoke

Simply tell Claude Code what you want to do with your course. Examples:

```
"Set up my AI Agent course repository"
"Create an assignment for Week 3 on building RAG systems"
"Show my course progress"
"Create a PR for my Week 5 assignment"
"Organize materials for Week 7"
```

The skill will automatically activate when your request matches course management activities.

### Use Cases

#### 1. Initial Course Setup
```
"Set up my 12-week AI Agent Developer Course repository structure"
```
Creates organized folders, templates, and tracking infrastructure.

#### 2. Create Weekly Assignments
```
"Create a Week 4 assignment on implementing memory systems for agents"
```
Generates a GitHub issue with learning objectives, tasks, and deliverables.

#### 3. Track Progress
```
"Show me my course progress and which weeks I've completed"
```
Lists all assignments with status, completion percentage, and upcoming work.

#### 4. Submit Assignments
```
"Create a pull request for my Week 6 assignment"
```
Commits your work and creates a PR linked to the assignment issue.

#### 5. Organize Materials
```
"Update the Week 8 documentation with my notes and examples"
```
Structures and commits course materials in organized folders.

## Course Structure

The skill organizes your repository as:

```
your-repo/
├── docs/
│   └── course/
│       ├── README.md
│       ├── week-01/
│       │   ├── README.md
│       │   ├── notes.md
│       │   └── examples/
│       ├── week-02/
│       ├── ...
│       └── week-12/
├── .github/
│   └── ISSUE_TEMPLATE/
│       └── weekly-assignment.md
└── [your code]
```

## Features

### 🎯 Assignment Issues
Each week's assignment is tracked as a GitHub issue with:
- Clear learning objectives
- Task checklists
- Deliverables list
- Resources and links
- Labels: `course`, `week-X`, `assignment`

### 📊 Progress Tracking
Uses GitHub features:
- **Milestones**: One per week (12 total)
- **Labels**: Organized categorization
- **Projects**: Optional kanban board for visual tracking
- **Issues**: Track assignment status

### 🔀 Branch Management
Creates organized branches:
- `course/week-X-assignment` - Weekly work
- `course/week-X-project` - Projects
- `course/experiments` - Experimentation

### 📝 Pull Requests
Structured PR workflow:
- Links to assignment issues
- Clear submission summaries
- Automated labels and milestones
- Review tracking

## GitHub MCP Tools Used

The skill leverages these MCP server capabilities:
- Create and manage issues
- Create and merge pull requests
- List and filter repository content
- Create branches
- Search code and issues
- Manage milestones and labels
- Access discussions

## Best Practices

1. **One Assignment Per Week**: Keep focused and organized
2. **Consistent Naming**: Use `week-XX` format everywhere
3. **Document As You Go**: Update READMEs with learnings
4. **Commit Regularly**: Small, meaningful commits
5. **Close Issues**: Mark assignments complete when done
6. **Review PRs**: Use PR reviews for self-assessment

## Example Workflow

### Week 3: Building a RAG System

1. **Create Assignment**:
   ```
   "Create Week 3 assignment on building RAG systems"
   ```
   → Creates Issue #3 with tasks and objectives

2. **Start Work**:
   ```
   "Create a branch for Week 3 work"
   ```
   → Creates `course/week-03-rag-system` branch

3. **Develop**:
   - Write code
   - Take notes in `docs/course/week-03/`
   - Commit regularly

4. **Submit**:
   ```
   "Create PR for Week 3 assignment"
   ```
   → Creates PR linking to Issue #3

5. **Complete**:
   - Review your own PR
   - Merge when satisfied
   - Close issue

## Troubleshooting

### GitHub MCP Tools Not Available

If you get errors about missing MCP tools:
1. Restart your Claude Code session
2. Verify `.mcp.json` exists in project root
3. Check `~/.claude/settings.json` has `"enableAllProjectMcpServers": true`
4. Verify GitHub PAT is valid in `.env` file

### Skill Not Activating

If the skill doesn't activate:
1. Use explicit phrasing: "Use the GitHub course manager skill to..."
2. Check skill is installed: `ls ~/.claude/skills/`
3. Verify SKILL.md exists and is readable
4. Restart Claude Code session

## Advanced Usage

### Custom Templates
Modify `.github/ISSUE_TEMPLATE/` to customize assignment format

### Multiple Courses
Use different label prefixes: `course-agents`, `course-llm`, etc.

### Team Courses
Share repository with collaborators, use PR reviews for peer feedback

### Progress Reports
Request weekly summaries to track learning velocity

## Integration with Your Course

This skill works alongside your course materials:
- **Week 1-3**: Foundation concepts → Document in `week-01/` through `week-03/`
- **Week 4-6**: Core agent concepts → Build projects in branches
- **Week 7-9**: Advanced topics → Create detailed examples
- **Week 10-12**: Capstone project → Major PR with full documentation

## Benefits

✅ **Organization**: All course work in one structured place
✅ **Tracking**: Visual progress through GitHub UI
✅ **History**: Git history of your learning journey
✅ **Portfolio**: Public repository showcases your work
✅ **Habits**: Practice professional development workflows
✅ **Automation**: Let Claude Code handle the admin work

## Next Steps

1. Restart Claude Code to load MCP server
2. Invoke the skill to set up your course structure
3. Create your first weekly assignment
4. Start building!

## Resources

- [GitHub MCP Server](https://github.com/github/github-mcp-server)
- [GITHUB_MCP_SETUP.md](../GITHUB_MCP_SETUP.md) - MCP installation guide
- [Claude Code Skills Documentation](https://docs.claude.com)

---

**Ready to organize your AI Agent Developer Course? Just ask Claude Code to help you get started!** 🚀
