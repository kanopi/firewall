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

The check costs one schema introspection per table — 0.48 ms against the 0.02 ms an
existence check costs — and is paid **once per table per PHP process**, not once per request
and not on a timer. Drift cannot appear mid-process: the declaration is fixed in the code
that is running, and the only thing that changes the live table is a migration, which brings
it closer. The same flag doubles as the record of having warned, so an operator who cannot
run the migration is not told once a minute for the life of the worker.

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
