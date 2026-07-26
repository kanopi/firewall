# Contributing

Thank you for your interest in contributing to Kanopi Firewall! We welcome contributions of all kinds, including code, documentation, bug reports, feature requests, and more.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/firewall.git
   cd firewall
   ```
3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/kanopi/firewall.git
   ```

## Development Setup

1. **Install Dependencies**:
   ```bash
   composer install
   ```

2. **Start Development Environment** (if using Docker):
   ```bash
   composer server:start
   ```

3. **Run Tests** to ensure everything is working:
   ```bash
   composer test
   ```

4. **Check Code Standards**:
   ```bash
   composer cs
   composer stan
   ```

## Git Workflow

We follow the Git Flow branching model:

- **Main branch**: `2.x` - This is our main development branch
- **Feature branches**: `feature/your-feature-name`
- **Bug fix branches**: `bug/issue-description`
- **Hotfix branches**: `hotfix/critical-fix`

### Creating a Branch

```bash
# Update your local repository
git checkout 2.x
git pull upstream 2.x

# Create a new branch
git checkout -b feature/my-new-feature
```

### Branch Naming Conventions

- `feature/` - New features or enhancements
- `bug/` - Bug fixes
- `hotfix/` - Critical fixes that need immediate attention
- `docs/` - Documentation updates
- `refactor/` - Code refactoring
- `test/` - Test additions or fixes

## Making Changes

### Before You Start Coding

1. **Create an Issue**: Before starting work, create or find an issue that describes what you're working on
2. **Discuss**: For major changes, discuss your approach in the issue before implementing

### While Coding

1. **Write Clean Code**: Follow PHP best practices and keep code readable
2. **Add Comments**: Document complex logic and explain what functions do
3. **Follow Existing Patterns**: Look at existing code and follow similar patterns
4. **Keep Changes Focused**: Each PR should address a single issue or feature

### Code Comments Example

```php
/**
 * Evaluates whether the given IP address falls within a CIDR block.
 * 
 * This method handles both IPv4 and IPv6 addresses and validates
 * that the IP and CIDR block are of the same type.
 */
protected function isInBlock(string $ip, string $cidr): bool
{
    // Validate CIDR format
    if (!str_contains($cidr, '/')) {
        return false;
    }
    
    // Implementation details...
}
```

## Submitting Changes

### Pre-Submission Checklist

Before creating a pull request:

- [ ] All tests pass (`composer test`)
- [ ] Code style checks pass (`composer cs`)
- [ ] Static analysis passes (`composer stan`)
- [ ] 100% test coverage for new code
- [ ] Documentation is updated
- [ ] Commit messages are clear
- [ ] Branch is up to date with `2.x`

### Creating a Pull Request

1. **Push your branch**:
   ```bash
   git push origin feature/my-new-feature
   ```

2. **Create the PR**:
   - Go to GitHub and create a pull request
   - Target the `2.x` branch
   - Reference the related issue (e.g., "Fixes #123")
   - Provide a clear description of changes

3. **PR Description Should Include**:
   - What the changes do
   - Why the changes are needed
   - How to test the changes
   - Any breaking changes

### Example PR Description

```markdown
## Description
This PR adds support for IPv6 CIDR blocks in the IpAddress plugin.

## Related Issue
Fixes #123

## Changes Made
- Updated `isInBlock()` method to handle IPv6 addresses
- Added validation for IPv6 CIDR notation
- Added comprehensive test coverage

## Testing
1. Configure the IpAddress plugin with IPv6 CIDR blocks
2. Test with both IPv4 and IPv6 client addresses
3. Verify correct blocking behavior

## Breaking Changes
None
```

## Types of Contributions

We welcome all types of contributions:

### Code Contributions
- New features
- Bug fixes
- Performance improvements
- Refactoring

### Non-Code Contributions
- Documentation improvements
- Bug reports
- Feature requests
- Example configurations
- Blog posts or tutorials
- Answering questions in issues

### Reporting Bugs

When reporting bugs, please include:
- Firewall version
- PHP version
- Relevant configuration
- Steps to reproduce
- Expected behavior
- Actual behavior
- Any error messages or logs

### Suggesting Features

When suggesting features:
- Check if it's already been suggested
- Explain the use case
- Provide examples of how it would work
- Consider if it fits the project's scope

## Communication

### Where to Get Help

- **GitHub Issues**: For bugs, features, and questions
- **GitHub Discussions**: For general discussions and ideas
- **Email**: sean@kanopi.com for specific questions

### Response Times

Response times may vary depending on the complexity of the issue and maintainer availability. We appreciate your patience and will respond as soon as possible.

### Being Respectful

- Be kind and respectful to other contributors
- Assume good intentions
- Be patient with response times
- Provide constructive feedback

## License and Attribution

### License

By contributing to Kanopi Firewall, you agree that your contributions will be licensed under the same MIT License that covers the project.

### Developer Certificate of Origin

By making a contribution to this project, you certify that:

1. The contribution was created in whole or in part by you and you have the right to submit it under the MIT license; or
2. The contribution is based upon previous work that, to the best of your knowledge, is covered under an appropriate open source license and you have the right to submit that work with modifications under the MIT license; or
3. The contribution was provided directly to you by some other person who certified (1), (2) or (3) and you have not modified it.

### Attribution

- Contributors retain copyright to their contributions
- Significant contributions may be acknowledged in release notes
- The project maintains copyright as "Kanopi Studios and contributors"

---
