# Development Setup

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
