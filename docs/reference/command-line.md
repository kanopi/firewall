# Command Line

The firewall ships one command, `firewall`, with a subcommand for each job (#289).
Installed as a dependency, it's at `vendor/bin/firewall`:

```bash
vendor/bin/firewall                          # list the commands
vendor/bin/firewall doctor config/firewall.yml
vendor/bin/firewall check --config=config/firewall.yml --url=/wp-login.php --explain
vendor/bin/firewall help rule                # the same as `firewall rule --help`
```

| Command | What it does | More |
|---|---|---|
| `firewall check` | Ask whether a given request would be blocked, and by what. `--lint` checks the configuration itself | [Check a Request](../how-to/checking-requests.md) |
| `firewall doctor` | Diagnose a live installation: storage, databases, GeoIP, every rule | [Diagnose an Installation](../how-to/diagnosing.md) |
| `firewall init` | Write a starting configuration | [Quick Start](../getting-started/quick-start.md#generate-a-configuration) |
| `firewall rule` | Add and remove rules without hand-editing YAML | [Manage Rules](../how-to/managing-rules.md) |
| `firewall block` | See who is blocked and why, and lift a block | [Storage](../configuration/storage.md#what-a-block-record-keeps) |
| `firewall challenge` | Read a challenge pass, and withdraw one | [Withdrawing a pass](../plugins/challenges.md#withdrawing-a-pass) |
| `firewall sources` | Refresh every `metadata.sources` list a config declares | [Sync Rule Sources](../how-to/syncing-sources.md) |
| `firewall migrate` | Bring existing tables up to the schema this release declares | [Migrate the Schema](../how-to/schema-migrations.md) |
| `firewall log-prune` | Delete log rows older than the retention window | [Logging](../configuration/logging.md#retention) |

`--help` after any command lists its arguments and exit codes. An unknown command exits `2`.

The command line is built on [Symfony Console](https://symfony.com/doc/current/components/console.html),
so every command also takes Console's own options:

| Option | What it does |
|---|---|
| `-h`, `--help` | The command's arguments, options and exit codes |
| `-n`, `--no-interaction` | Ask nothing. `firewall init` takes its defaults |
| `--ansi`, `--no-ansi` | Force colour on or off |
| `-v`, `-vv`, `-vvv` | More output, where a command has more to say |
| `-V`, `--version` | The installed version |

Console's own `--quiet` is not one of them. `doctor`, `migrate`, `sources` and `log-prune`
each have a `--quiet` of their own, meaning "only warnings and failures", and that's the one
that applies.

**Shell completion.** `firewall completion` prints a completion script for bash, zsh or
fish. For bash:

```bash
vendor/bin/firewall completion bash | sudo tee /etc/bash_completion.d/firewall
```

**Exit codes are each command's own.** An option a command doesn't have, or one missing its
value, exits with that command's usage code: `2` for most, and `64` for `firewall check`,
where `1` means "would be blocked".

## The old script names

Before 2.38.0 each command was its own script: `firewall-check`, `firewall-doctor`,
`firewall-init`, `firewall-rule`, `firewall-block`, `firewall-challenge`, `firewall-sources`,
`firewall-migrate` and `firewall-log-prune`. **They still work, and are deprecated.** Each
one runs exactly what its subcommand runs, with the same arguments, output and exit code, so
nothing that calls one breaks. They will be removed in **3.0**.

Since 2.38.0 the commands are stricter about their arguments. An option a command doesn't
have used to be ignored by `check` and `init`, so a typo like `--cofig=` did nothing. It's
now an error, with the command's usage exit code. `check --ip 1.2.3.4`, with a space instead
of `=`, now works as it reads, where before it silently stopped reading the options.

Run at a terminal, an old name prints one line to stderr saying what to use instead. Run
from cron, CI or a deploy hook, it says nothing, because cron emails whatever a job writes
and a notice on every run would become a daily email.

Change each call by replacing the hyphen with a space:

```diff
-30 4 * * * cd /srv/app && vendor/bin/firewall-log-prune config/firewall.yml --quiet
+30 4 * * * cd /srv/app && vendor/bin/firewall log-prune config/firewall.yml --quiet
```

```diff
-vendor/bin/firewall-doctor config/firewall.yml --quiet
+vendor/bin/firewall doctor config/firewall.yml --quiet
```
