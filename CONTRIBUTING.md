# Contributing

Keep runtime dependencies limited to the Python standard library. Contributions should preserve local, read-only behavior and distinguish missing evidence from a measured zero.

Add tests with temporary files or fictional fixtures. Never attach real observations, private paths, credentials, prompts, HTTP bodies, or model responses. Screenshots must use the bundled demo and visibly retain its fictional-data label.

Run the test suite and public-tree check in the README before proposing changes. A new source adapter must document its exact metadata allowlist, time semantics, retention/coverage limits and permission requirements. Network access, new listeners, credentials, process control, or system configuration changes are outside the current collector contract.
