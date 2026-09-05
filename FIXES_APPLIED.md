# Fixes Applied

The following source changes were applied and locally verified.

| Area | Fix | Verification |
|---|---|---|
| Combined reports | HTML and JSON now receive distinct absolute paths, such as `report.html` and `report.json`. | `--report both --output regression_check` created both valid files. |
| Configuration | Bundled `config.yaml` is resolved from the project root, while explicit custom paths remain supported. | Absolute-path CLI invocation from outside the project directory completed successfully against a local fixture. |
| Directory brute force | Wordlist paths are deduplicated and capped at 250 by default; concurrency is bounded; probe timeout is shorter; directory probes use zero retries. | A 30-path local regression completed in 2.98 seconds with no errors. |
| Existing features | Dashboard, mass scan, ASN module, Nuclei adapter, and scanner progress callback remain included. | Compilation, imports, CLI help, local dashboard/API, and bounded mass-scan tests passed. |

Nuclei still requires the separate Nuclei executable and a local template directory. The project does not bundle third-party templates or credentials.
