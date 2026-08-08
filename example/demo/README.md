# Lite Firewall local demo

A throwaway harness for poking at the firewall in a browser. Demonstrates all
three response modes (`allow`, `block`, `challenge`) and all four built-in
challenge providers (`math`, `altcha`, `turnstile` and `recaptcha`) side by
side, and ships a
production-shaped nginx → php-fpm stack so you can run perf experiments against
something that looks like a real deployment.

**Full documentation:
[Demo Application](../../docs/guides/demo.md)** — routes,
all three run modes, the scripted challenge walkthrough, perf testing, and
repeat-offender behavior.

## TL;DR

```bash
composer demo           # PHP built-in server on http://localhost:8000
composer demo:workers   # same, with 8 worker processes
composer demo:reset     # wipe stored blocks between runs
composer demo:perf      # nginx + php-fpm stack
composer demo:perf:down
```

## Editing these docs

Built from [`docs/guides/demo.md`](../../docs/guides/demo.md). Change the
Markdown there, not this file.
