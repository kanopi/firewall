# URL Plugin

**Namespace**: `\Kanopi\Firewall\Plugins\Url`

Evaluates requests based on URL components and request parameters.

## Configuration Example

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: block
    weight: 0
    enable: true
    config:
      # Block all POST requests
      - "method:POST"

      # Block specific paths
      - "path:/wp-admin"
      - "path@starts_with:/admin"
      - "path@contains:phpmyadmin"
      - 'path@regex:/\.(sql|bak|old)$/i'

      # Block based on host
      - "host:malicious.example.com"
      - "host@ends_with:.suspicious.com"

      # Block based on query parameters
      - "query.cmd@exists"
      - "query.action:delete"

      # Block based on POST data
      - "post.username:admin"
      - "post.action@in:drop,truncate,delete"

      # Block based on headers
      - "header.user-agent@contains:bot"
      - "header.x-forwarded-for@exists"

      # Complex URL rules
      - type: AND
        rules:
          - "method:POST"
          - "path@starts_with:/api"
          - "!header.authorization@exists"
```

## Available Variables

- `method` - HTTP method (GET, POST, PUT, DELETE, etc.)
- `host` - Hostname from the request
- `path` - URI path (e.g., /admin/users)
- `scheme` - URL scheme (http or https)
- `port` - Port number
- `query.*` - Query parameters (e.g., query.page, query.id)
- `post.*` - POST body parameters
- `header.*` - HTTP headers (e.g., header.user-agent)
- `cookie.*` - Cookie values
