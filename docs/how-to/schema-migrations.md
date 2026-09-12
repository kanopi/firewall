# Schema Migrations

The firewall's database tables are created on first write. Until v2.22.0 they were then
never touched again, which meant a release that added a column or an index reached only
installations created after it.

That debt was visible in the release notes rather than in the code. v2.19.0 added an index
to the rate limit table and asked anyone with an existing one to run a `CREATE INDEX` by
hand; the log table's own documentation said that a new column meant dropping the table and
recreating it, *"which loses history but breaks nothing"* — for a table whose entire purpose
is holding history.

`bin/firewall-migrate` is that instruction, executable.

## Running it

```bash
bin/firewall-migrate firewall.yml --dry-run
```

```
  ✓ storage                      up to date
  + rate limit (plugin 0)        firewall_rate_limit_storage.firewall_rate_limit_storage_rule_window_idx index
      CREATE INDEX firewall_rate_limit_storage_rule_window_idx ON firewall_rate_limit_storage (rule, timestamp)
  ✓ logger (handler 0)           up to date

1 change pending.
```

```bash
bin/firewall-migrate firewall.yml
```

It takes the same configuration files the firewall does, and covers every database-backed
thing they declare: `storage:`, each rate limit plugin's `metadata.storage`, and each
`DatabaseHandler` under `logger:`.

| Option | |
|---|---|
| `--dry-run` | Report what is missing, and the exact statements, without running them. |
| `--quiet` | Only report changes and failures. |

| Exit code | |
|---|---|
| `0` | Every table matches, or was brought up to date. |
| `1` | At least one change could not be applied. |
| `2` | The configuration could not be read, or declares no database tables. |
| `3` | `--dry-run` only: changes are pending. Lets a deploy gate on it without parsing output. |

## It only ever adds

It adds columns and indexes that are missing. It never drops a column, never renames one,
and never rewrites an existing one, so **no sequence of runs can lose a row**. Running it
against an already-current schema does nothing at all.

That ceiling is deliberate, and it is also what makes the comparison trustworthy. A table
that DBAL has just created does not compare equal to its own declaration: introspecting one
back reports a platform collation the declaration never set — `BINARY` on SQLite, the server
default on MySQL — so every string and text column looks "changed" on a table with no drift
whatsoever. Acting on a changed column would mean rewriting every healthy table on every
run. Whether a column or index *exists* has no such ambiguity, so that is the only question
asked.

The cost of that decision is real and worth stating: **a release that widens or retypes a
column is not covered here** and will need an `ALTER` you run yourself. No release has done
that, and the release that does will say so in its notes.

## Changes it refuses

A column declared `NOT NULL` with no default cannot be added to a table that already has
rows — SQLite and PostgreSQL both reject it, and MySQL quietly invents a value, which is
worse. Rather than attempt it, the migrator reports it:

```
  ✗ logger (handler 0)           firewall_log.severity_hint column
      refused: declared NOT NULL with no default, which cannot be added to a table that has rows
```

It refuses this on an empty table too, where it would in fact have worked. A migration whose
outcome depends on whether the table happens to have rows yet is one that passes in staging
and fails in production.

A refusal does not stop the rest of the run: one column that cannot be added safely is not a
reason to leave an index missing as well.

## The startup warning

You do not have to remember to check. When a table is behind, the firewall says so:

```
firewall.WARNING: Database table is behind the schema this release declares
  {"table":"firewall_rate_limit_storage",
   "missing":["index firewall_rate_limit_storage_rule_window_idx"],
   "remedy":"Run bin/firewall-migrate to add them, or bin/firewall-migrate --dry-run to see the statements first."}
```

`warning`, not `error`: everything the table is asked to do today, it still does. A missing
index makes a query slow, not wrong.

### What the check costs, and why it is sampled

Comparing a table against the declaration means introspecting it, and that is not free:

| `DatabaseStorage`, 2 tables, over a socket to MariaDB | |
|---|---|
| Asking whether the tables exist | 0.70 ms |
| Introspecting them | **4.06 ms** |

So the check is **drawn for, not always run** — 1% of constructions by default. Two things
make that the right shape rather than a fudge:

- **A per-process flag is not enough on its own.** Under PHP-FPM a worker persists, so
  "check once per process" really is once per worker. Under mod_php or CGI the process *is*
  the request, so the same flag means once per request — and a deployment declaring four
  tables would pay about 12 ms of introspection on every one of them.
- **The warning does not need to be prompt.** An operator learns within a few hundred
  requests that an index is missing, which is soon enough for something that has been missing
  since the last upgrade.

At 1% the amortised cost is small enough to be unmeasurable against the construction it sits
in. Set it lower, or turn it off:

```yaml
storage:
  type: "Kanopi\\Firewall\\Storage\\DatabaseStorage"
  config:
    schema_check_probability: 0    # never check on the request path
```

Accepted by `DatabaseStorage`, `DatabaseRateLimitStorage` and `DatabaseHandler`, and it is
deliberately the same shape as the handler's existing `prune_probability`: the same problem —
periodic maintenance that must not live on the request path — with the same escape hatch.

**`0` does not disable migration**, only the warning. `bin/firewall-migrate --dry-run` answers
the question deterministically and exits `3` when something is pending, which is the better
place for it if you gate schema changes on deploy.

### When it cannot check

A database user without the privilege to read `information_schema` fails this check. That is
logged at `debug` and stepped over — comparing the schema is not the job, enforcing the rules
is.

## Migrating from your own code

The bin script is a thin wrapper. Any consumer of `DatabaseTrait` — `DatabaseStorage`,
`DatabaseRateLimitStorage`, `DatabaseHandler` — exposes the same two methods, which is what
an integration with its own status report or update hook should call:

```php
$storage = new DatabaseStorage($config);

// Report. Introspects, changes nothing.
foreach ($storage->pendingSchemaChanges() as $change) {
    // ['table' => …, 'kind' => 'column'|'index', 'name' => …,
    //  'sql' => […], 'safe' => bool, 'reason' => …]
}

// Apply. Returns every pending change, each marked with whether it ran.
foreach ($storage->migrateSchema() as $result) {
    if (!$result['applied']) {
        // $result['reason'] says why
    }
}
```

Neither is called from the request path. An `ALTER TABLE` takes a lock, and a firewall that
decides to take one on a cold cache under load is not something to switch on by default.
