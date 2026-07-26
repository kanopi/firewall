# Creating Custom Presets

You can create your own presets by following the same structure:

```yaml
# presets/my-custom-rules.yml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: allow
    weight: -200
    enable: true
    config:
      - path:/my-allowed-path

  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: block
    weight: -100
    enable: true
    config:
      - path:/my-blocked-path
      - path@contains:/sensitive
```

Then include it in your main config:

```yaml
configs:
  - presets/my-custom-rules.yml
```

Both entries will be appended to the combined `plugins:` list at load time. The `allow` entry runs first (lower `weight`) so trusted paths are short-circuited before the block rules execute.
