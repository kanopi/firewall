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
- `query_count.*` - How many values the client sent for one query parameter
  (`query_count.f`), as a number. `query_count` alone counts every parameter. See below.
- `post.*` - POST body parameters
- `header.*` - HTTP headers (e.g., header.user-agent)
- `cookie.*` - Cookie values

### Counting a parameter's values

`query.f` resolves to nothing when the client sends `f` as a list (`f[]=a&f[]=b`). That's
deliberate, so `contains` can't match across values sent separately, and it means a list
can't be compared. `query_count.f` is how many values of `f` the client sent, counted from
the raw query string, so every spelling counts the same (#440):

| Query | `query_count.f` |
|---|---|
| `f[0]=a&f[1]=b&f[2]=c` | 3 |
| `f[]=a&f[]=b` | 2 |
| `f[0]=a&f[7]=b`, `f[x]=a&f[y]=b` | 2 |
| `f=a&f=b`, which PHP reduces to one | 2 |
| `f%5B0%5D=a&q=x&f%5B1%5D=b` | 2 |
| `f[x][y]=a` | 1 (each pair is one value of its top-level name) |
| no `f` at all | 0 |

The name is case-sensitive, as the application reads it, and a name containing a dot is
read whole (`query_count.filter.type`). Use the numeric operators:
`query_count.f@greater_than:3`. See [Facet crawling](../how-to/recipes.md#stop-facet-crawling).
