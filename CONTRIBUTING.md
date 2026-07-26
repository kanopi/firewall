# Contributing to Kanopi Firewall

Thank you for your interest in contributing to Kanopi Firewall! We welcome contributions of all kinds, including code, documentation, bug reports, feature requests, and more.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Git Workflow](#git-workflow)
- [Making Changes](#making-changes)
- [Testing Requirements](#testing-requirements)
- [Code Style and Standards](#code-style-and-standards)
- [Documentation](#documentation)
- [Submitting Changes](#submitting-changes)
- [Types of Contributions](#types-of-contributions)
- [Communication](#communication)
- [License and Attribution](#license-and-attribution)

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

## Testing Requirements

**All new features must have 100% test coverage.**

### Writing Tests

1. **Unit Tests**: Required for all new code
   - Test individual methods and classes in isolation
   - Mock dependencies when appropriate
   - Place in `tests/Unit/` directory

2. **Integration Tests**: Required when:
   - Testing interaction between multiple components
   - Testing database or file system operations
   - Testing the full request/response cycle
   - Place in `tests/Integration/` directory

### Test Structure Example

```php
<?php

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use PHPUnit\Framework\TestCase;
use Kanopi\Firewall\Plugins\YourPlugin;

class YourPluginTest extends TestCase
{
    /**
     * Tests that the plugin correctly identifies blocked patterns.
     */
    public function testBlocksMaliciousPattern(): void
    {
        // Arrange
        $plugin = new YourPlugin([], ['pattern' => 'malicious']);
        
        // Act
        $result = $plugin->evaluate($this->createRequest('malicious-content'));
        
        // Assert
        $this->assertTrue($result);
    }
}
```

### Running Tests

```bash
# Run all tests
composer test

# Run with coverage report
composer test:coverage

# Run only unit tests
composer phpunit:unit

# Run only integration tests
composer phpunit:integration
```

## Code Style and Standards

### Automated Checks

Before submitting your PR, ensure all checks pass:

```bash
# Check code style
composer cs

# Fix code style automatically
composer cs:fix

# Run static analysis
composer stan

# Run all checks
composer check
```

### Manual Standards

1. **Variable Naming**: Use descriptive names
   - Good: `$clientIpAddress`, `$rateLimitWindow`
   - Bad: `$ip`, `$rlw`

2. **Method Length**: Keep methods focused and short (under 20 lines when possible)

3. **Class Responsibility**: Follow Single Responsibility Principle

4. **Error Handling**: Always handle edge cases and potential errors

## Documentation

### When to Update Documentation

Update documentation when you:
- Add new features
- Change existing functionality
- Add new configuration options
- Change plugin behavior
- Add new plugins

### Where Documentation Lives

There is no separate docs site — everything ships in the repository:

| File | Scope |
|------|-------|
| `README.md` | The configuration reference. Every config key, plugin, storage backend, and public API belongs here. |
| `presets/README.md` | The shipped presets: what each one blocks, how to compose and override them, false positives. |
| `presets/RATE-LIMITING-REFERENCE.md` | Per-rule detail for `rate-limiting.yml`. |
| `example/README.md` | The Docker sandbox, GeoIP setup, and worked blocking examples. |
| `example/demo/README.md` | The runnable demo app. |
| `tests/Performance/README.md` | The load-testing harness. |
| `CONTRIBUTING.md` | This file — process, not product. |

If you add a preset, a `bin/` script, or an example config, it needs an entry in the relevant README. A committed file that no document mentions is a documentation bug.

### What to Document

1. **README.md**: Update when adding features or changing usage
2. **PHPDoc**: Every class, interface, trait, enum, and method — including constructors and private helpers — carries a docblock. Use `{@inheritdoc}` for interface implementations and overrides. This is enforced by review, not tooling, so don't rely on CI to catch a missing one.
3. **Code Comments**: Document *why*, not *what*. Explain non-obvious decisions, security reasoning, and workarounds.
4. **Test Descriptions**: Clearly describe what each test verifies
5. **Configuration Examples**: Provide examples for new configuration options

### Documenting Public API

Anything an integrator can call needs more than a docblock — it needs a README section with a working example. That includes:

- New config keys (and their defaults)
- New plugins, storage backends, or challenge providers
- New static methods on `LoggingFactory`, `TokenSubstitute`, etc.
- New exception types, and which mode throws them

Opt-in or security-relevant behavior deserves particular care: if a feature is disabled by default, or fails closed, say so explicitly and show the call that enables it.

### Documentation Checklist

- [ ] Updated README.md if adding/changing features
- [ ] Every new class and method has a docblock
- [ ] Public API additions have a README example, not just a docblock
- [ ] Added inline comments for complex code
- [ ] Included configuration examples
- [ ] Updated any affected examples in `/example` directory
- [ ] Any new preset / script / example file is referenced from a README
- [ ] Existing examples still reflect actual behavior (config keys, defaults, method names)

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

Thank you for contributing to Kanopi Firewall! Your efforts help make this project better for everyone.