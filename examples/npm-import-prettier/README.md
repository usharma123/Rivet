# npm import: prettier

Import prettier from npm through a Rivet registry, check what the registry signed, and run it in the sandbox:

```sh
rivet import npm:prettier
rivet inspect prettier
rivet run prettier --version
rivet verify prettier
```

`import` resolves the newest release outside the cooldown window, has the registry verify npm's integrity, provenance and audit, then installs the verified tree under `~/.rivet/tools`. `run` refreshes the signed statements, re-hashes the installed files and starts prettier with network off and the home directory hidden.
