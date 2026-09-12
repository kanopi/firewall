# Managing Rules from the Command Line

`bin/firewall-rule` adds, removes and disables rules without opening a YAML file.

```console
$ firewall-rule init firewall.yml          # once
$ firewall-rule add firewall.yml --ip=203.0.113.0/24 --name=scraper-farm
$ firewall-rule list firewall.yml
$ firewall-rule disable firewall.yml scraper-farm
$ firewall-rule remove firewall.yml scraper-farm
```

## It does not edit your configuration, and that is the point

Symfony's YAML has no comment-preserving round trip. Parse a file and dump it back, and this
is what happens:

```yaml title="before"
# a comment that matters
global:
  # why this is log
  mode: log
plugins:
  - plugin: A   # trailing note
```

```yaml title="after Yaml::dump(Yaml::parse(...))"
global:
  mode: log
plugins:
  - plugin: A
```

[`firewall-init`](../getting-started/quick-start.md) generates a heavily commented config
precisely so you read it and edit it. A command whose first `add` silently deleted all of
that would have taken something away, and you would not find out until you next opened the
file.

So `firewall-rule` owns a **separate file**, rewrites only that one, and includes it beside
yours:

```yaml title="firewall.yml — yours, never modified"
configs:
  - "firewall-managed.yml"

global:
  mode: block
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    # ... everything here stays exactly as you wrote it
```

A root-level `plugins:` list **appends** across includes, so managed rules run alongside
yours, each keeping its own `config:`.

### What that means you cannot do

Nothing merges into an existing rule. Declaring the same rule twice gives you two rules, not
one modified one — so:

| | Rules `firewall-rule` wrote | Rules you wrote |
|---|---|---|
| `list` | ✅ | ✅ |
| `add` | ✅ | — |
| `remove` / `disable` / `enable` | ✅ | ❌ refused, by name |

Asking it to disable one of yours does not fail vaguely:

```
Refused: "xmlrpc" is one of your own rules, not one this command wrote.

Rewriting your configuration would destroy its comments, which is the whole
reason there are two files. Edit it where it is declared, or set
`enable: false` on that entry.
```

## Setting it up

Run `init` **before** adding the `configs:` line, and in that order:

```console
$ firewall-rule init firewall.yml
Created firewall-managed.yml

Include it from your configuration, now that the file exists:

  configs:
    - "firewall-managed.yml"
```

!!! warning "The order is not cosmetic"

    A `configs:` entry naming a file that does not exist is a **load failure, not a skipped
    line** — the whole document comes back empty, so every rule in your configuration stops
    being configured. Write the file first.

`add` checks this for you: after writing, it reloads the configuration and confirms the rule
is actually there. If nothing includes the managed file it says so and exits non-zero, because
"the command worked" and "the rule is in force" are different facts and only one of them
matters during an incident.

## Adding rules

```console
$ firewall-rule add firewall.yml --ip=198.51.100.0/24 --response=allow --name=office --weight=-100
$ firewall-rule add firewall.yml --path=/xmlrpc.php --name=no-xmlrpc
$ firewall-rule add firewall.yml --plugin=agent --rule="contains:sqlmap" --name=sqlmap
```

| Option | |
|---|---|
| `--plugin=NAME` | `ip`, `url`, `agent`, `asn`, `geo`, or a class name. Default `ip` |
| `--response=NAME` | `block`, `allow`, `challenge`. Default `block` |
| `--rule=VALUE` | A `config:` entry, in that plugin's own syntax. Repeatable |
| `--ip=VALUE` | Shorthand for `--plugin=ip --rule=VALUE`. Repeatable |
| `--path=VALUE` | Shorthand for `--plugin=url --rule=path:VALUE`. Repeatable |
| `--name=NAME` | What the log will call it. Generated if omitted |
| `--weight=N` | Evaluation order, lower first. Default `0` |

An allow rule with a negative weight is consulted before any block rule, which is how you keep
your office or a monitoring vendor out of trouble.

Every rule gets a name, generated if you do not supply one. An unnamed rule is one the log
cannot tell from every other rule of the same class — and one this command could never find
again to remove.

## Listing

```console
$ firewall-rule list firewall.yml
yours     block   on    0      xmlrpc   (declared in your own configuration)
managed   allow   on    -100   office

2 rules. `managed` ones live in firewall-managed.yml and can be changed from here.
```

`--json` gives the same thing machine-readably. The `managed` column is the useful part: a
listing that did not draw the distinction would invite `remove` on a rule that cannot be
removed, and the refusal would arrive after you had decided it was gone.

## Disabling rather than removing

```console
$ firewall-rule disable firewall.yml office
```

The definition stays in the file with `enable: false`. An incident is not the moment to
reconstruct a rule from memory, and the next person can read what it was.

## Options everywhere

| Option | |
|---|---|
| `--managed=PATH` | The file this owns. Default `firewall-managed.yml` beside the first config given |
| `--dry-run` | Report what would change and write nothing |
| `--json` | Machine-readable output |

## Exit codes

| | |
|---|---|
| `0` | Done, or the listing printed |
| `1` | Refused: no such managed rule, a name already taken, one of your own rules, a rule written but not included, or the file could not be written |
| `2` | The configuration could not be read, or the arguments made no sense |

## Related

- [Seeing and lifting blocks](diagnosing.md) — `bin/firewall-block` manages the
  *runtime* block list, which is a different question from the rules in a config
- [Loading & Includes](../configuration/loading-and-includes.md) — the merge semantics this
  relies on
