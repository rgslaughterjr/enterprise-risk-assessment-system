---
name: github-course-manager
description: Manage AI Agent Developer Course (12 weeks) using GitHub MCP. Use when the user wants to track course progress, create weekly assignments, manage pull requests for course work, organize course materials, or set up course repository structure.
---

# GitHub Course Manager Skill

Manage the 12-week AI Agent Developer Course using GitHub MCP server capabilities. This skill helps organize course materials, track progress, and manage assignments through GitHub issues, pull requests, and project boards.

## Prerequisites

- GitHub MCP server must be installed and configured (see GITHUB_MCP_SETUP.md)
- Repository must be set up for the course
- GitHub Personal Access Token with appropriate permissions (repo, workflow, read:org)

## Course Structure

The 12-week AI Agent Developer Course typically includes:
- **Week 1-3**: Foundations (LLM basics, prompt engineering, agent frameworks)
- **Week 4-6**: Core Concepts (memory, tools, planning, reasoning)
- **Week 7-9**: Advanced Topics (multi-agent systems, RAG, fine-tuning)
- **Week 10-12**: Projects (capstone project, deployment, production)

## Capabilities

This skill helps you:
1. Create weekly assignment issues with templates
2. Track course progress through GitHub Projects/Issues
3. Manage branches for different course weeks
4. Create pull requests for weekly submissions
5. Organize course materials in repository
6. Set up milestone tracking for the 12 weeks
7. Generate weekly progress reports
8. Manage course-related documentation

## Workflow

When invoked, follow this workflow based on user request:

### 1. Initial Course Setup

If the user wants to set up the course repository:

**Tasks:**
1. Analyze the current repository structure
2. Create a `docs/course/` directory structure:
   ```
   docs/course/
   ├── README.md              # Course overview
   ├── week-01/               # Weekly folders
   ├── week-02/
   ├── ...
   ├── week-12/
   └── resources/             # Additional resources
   ```
3. Create `.github/ISSUE_TEMPLATE/` for weekly assignments
4. Set up GitHub Project board for course tracking (if user wants)
5. Create milestones for each week
6. Commit and push changes

### 2. Weekly Assignment Creation

When user requests to create a weekly assignment:

**Tasks:**
1. Ask the user which week (1-12) and assignment details
2. Create a GitHub issue using the GitHub MCP tools with:
   - Title: "Week X: [Assignment Title]"
   - Labels: `course`, `week-X`, `assignment`
   - Milestone: Week X
   - Body with assignment details, learning objectives, deliverables
3. Create a corresponding branch: `course/week-X-assignment`
4. Update course tracking document
5. Provide summary of created issue and branch

**Issue Template Format:**
```markdown
# Week X: [Assignment Title]

## 🎯 Learning Objectives
- [Objective 1]
- [Objective 2]

## 📚 Prerequisites
- [Prerequisite 1]
- [Prerequisite 2]

## 🔨 Tasks
- [ ] Task 1
- [ ] Task 2
- [ ] Task 3

## 📦 Deliverables
- [ ] Code implementation
- [ ] Documentation
- [ ] Tests

## 📖 Resources
- [Resource 1](link)
- [Resource 2](link)

## ⏰ Deadline
Week X - Day Y

## 🆘 Help & Support
If you encounter issues, please comment on this issue or reach out in discussions.
```

### 3. Progress Tracking

When user wants to check course progress:

**Tasks:**
1. Use GitHub MCP to list issues with labels: `course`, `assignment`
2. Check status of each week's issues (open/closed)
3. Generate a progress report showing:
   - Completed weeks
   - Current week
   - Upcoming assignments
   - Overall completion percentage
4. Identify any overdue assignments
5. Present findings in a formatted table/summary

### 4. Pull Request Management

When user wants to submit or review weekly work:

**Tasks:**
1. Check current branch and uncommitted changes
2. If creating new PR:
   - Ensure work is committed
   - Push to branch (e.g., `course/week-X-assignment`)
   - Create PR using GitHub MCP with:
     - Title: "Week X Assignment Submission"
     - Body: Link to issue, summary of changes
     - Labels: `course`, `week-X`, `submission`
3. If reviewing existing PRs:
   - List all open course-related PRs
   - Show PR details, files changed, status checks
   - Provide summary for user

### 5. Course Material Organization

When user wants to organize course materials:

**Tasks:**
1. Create/update weekly README files in `docs/course/week-XX/`
2. Structure should include:
   - Week overview
   - Key concepts covered
   - Links to code examples
   - Additional reading/resources
   - Assignment links
3. Update main course README with links to all weeks
4. Commit and push changes

### 6. Milestone Management

When user wants to manage course milestones:

**Tasks:**
1. Use GitHub MCP to list/create milestones for each week
2. Assign issues to appropriate milestones
3. Track milestone completion status
4. Generate milestone summary report

### 7. Branch Management

When user wants to manage course branches:

**Tasks:**
1. List all course-related branches
2. Create new branch for specific week: `course/week-X-[topic]`
3. Clean up merged/stale branches if requested
4. Show branch status and recent commits

### 8. Discussion & Collaboration

When user wants to engage with course discussions:

**Tasks:**
1. Use GitHub MCP to list/create discussions
2. Organize discussions by categories:
   - Q&A
   - Weekly reflections
   - Project ideas
   - General
3. Link discussions to relevant issues/PRs

## Best Practices

1. **Consistent Naming**: Use `week-XX` format for all course-related items
2. **Labels**: Always use appropriate labels (course, week-X, assignment, submission)
3. **Documentation**: Keep course README updated with progress
4. **Commits**: Make meaningful commits with clear messages
5. **Branches**: One branch per assignment/week
6. **Issues**: Close issues when assignments are completed
7. **Reviews**: Use PR reviews for assignment feedback

## Example Commands

The user might invoke this skill by saying:
- "Set up my course repository structure"
- "Create an assignment for Week 3 on RAG systems"
- "Show my course progress"
- "Create a PR for Week 5 assignment"
- "Organize materials for Week 7"
- "Check all open course issues"

## GitHub MCP Tools to Use

When executing tasks, use these MCP tools (they should be available after restart):
- `mcp__github__create_issue` - Create weekly assignments
- `mcp__github__list_issues` - Track progress
- `mcp__github__create_pull_request` - Submit assignments
- `mcp__github__create_branch` - Create weekly branches
- `mcp__github__get_file_contents` - Read course materials
- `mcp__github__push_files` - Update documentation
- `mcp__github__search_issues` - Find specific assignments
- `mcp__github__update_issue` - Update assignment status

## Error Handling

If GitHub MCP tools are not available:
1. Inform user they need to restart Claude Code session
2. Verify `.mcp.json` configuration exists
3. Check that `enableAllProjectMcpServers` is true in settings
4. Provide fallback instructions for manual GitHub operations

## Output Format

Always provide clear, structured output:
```markdown
## ✅ Task Completed

### What was done:
- [Action 1]
- [Action 2]

### GitHub Resources Created:
- Issue #123: Week X Assignment
- Branch: course/week-X-topic
- PR #456: Week X Submission

### Next Steps:
1. [Next step 1]
2. [Next step 2]

### Links:
- [Issue](link)
- [PR](link)
- [Branch](link)
```

## Wrap Up

After completing any workflow:
1. Provide a summary of actions taken
2. Include links to created GitHub resources
3. Suggest next steps for the user
4. Offer to help with related tasks
5. Remind user to review changes on GitHub

Remember: This is a learning journey! Encourage the user and help them stay organized throughout their 12-week AI Agent Developer Course.
