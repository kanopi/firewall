# Contributing to Kanopi Firewall

Thank you for your interest in contributing! We welcome contributions of all
kinds — code, documentation, bug reports, and feature requests.

**The full contributing guide lives at
[kanopi.github.io/firewall/contributing](https://kanopi.github.io/firewall/contributing/).**

| Page | Covers |
|---|---|
| [Contributing](https://kanopi.github.io/firewall/contributing/) | Git workflow, branch naming, commit conventions, the PR checklist, and how to report bugs or suggest features |
| [Development Setup](https://kanopi.github.io/firewall/contributing/development/) | Local environment, and the PHPCS / PHPStan / Rector checks |
| [Testing](https://kanopi.github.io/firewall/contributing/testing/) | Test requirements, structure, coverage, and running the suite |
| [Writing Documentation](https://kanopi.github.io/firewall/contributing/documentation/) | How to change this documentation site |

## The short version

```bash
git clone git@github.com:kanopi/firewall.git
cd firewall
composer install

git switch -c feature/your-change 2.x

# ... make your change, with tests ...

composer test        # PHPUnit, unit + integration
composer cs          # PHPCS
composer stan        # PHPStan at level max
composer check       # all three
```

Then open a pull request against `2.x`.

### Before you submit

- [ ] Tests cover the new code, and `composer test` passes
- [ ] `composer check` passes (style, static analysis, Rector)
- [ ] Every new class and method has a docblock
- [ ] Public API additions are documented on the docs site with a working example
- [ ] Documentation updated in [`docs/`](docs/) if behavior or config changed

### Documentation changes

Documentation is Markdown in [`docs/`](docs/), built with MkDocs. Every page on
the site has an **edit** pencil that opens the right file in GitHub's web
editor and walks you through opening a PR — no local setup required.

To preview locally:

```bash
python3 -m venv .venv-docs
source .venv-docs/bin/activate
pip install -r docs/requirements.txt
mkdocs serve
```

See [Writing Documentation](https://kanopi.github.io/firewall/contributing/documentation/)
for page conventions, code-snippet options, and screenshot guidelines.

## Code of conduct

Be respectful and constructive. Assume good faith, critique the code rather
than the person, and remember that maintainers and contributors are
volunteering their time.

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE).
