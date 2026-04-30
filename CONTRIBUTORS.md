# Contributors

A list of people who have contributed to this project. Thank you!

## Maintainer

- **V1D1AN** — project owner, S1EM platform integration
  - GitHub: [@V1D1AN](https://github.com/V1D1AN)

## Contributors

- **Claude (Anthropic)** — initial code generation, STIX 2.1 conversion logic, OpenAPI endpoint mapping, group-name resolution heuristics (alias, x_mitre_aliases, normalized variants)
  - Model: Claude Opus 4.7
  - Role: AI pair-programmer

## Acknowledgments

- **Julien Mousqueton** ([@JMousqueton](https://github.com/JMousqueton)) — creator of [Ransomware.live](https://www.ransomware.live/) and the underlying API.
- **Sudesh Yalavarthi** — author of the original community `connector-ransomwarelive` (v2 API), which inspired the structure of the related PRO connector.
- **Filigran** — for OpenCTI and the connector SDK.
- **Jacox98** — for the [n8n-nodes-ransomware-live](https://github.com/Jacox98/n8n-nodes-ransomware-live) community node, which served as a reference for the PRO API endpoint mapping.

## How to contribute

Pull requests are welcome. For substantial changes, please open an issue
first to discuss what you would like to change.

When opening a PR:

1. Add yourself to this `CONTRIBUTORS.md` file.
2. Make sure `python -m py_compile` passes on every changed file.
3. Update the `CHANGELOG.md` under the `Unreleased` section.
4. Keep commits focused — one logical change per commit.
