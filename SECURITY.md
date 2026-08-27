# Security Policy

This repository is the rails layer of a cybersecurity audit workbench: an
evidence ledger, a deterministic scan/match engine, and reporting. It has no
network scanning capability and does not connect to client systems, but it
does handle client-provided evidence (asset inventories, SBOMs, configuration
exports), so treat vulnerabilities affecting evidence confidentiality, ledger
integrity, or scoring correctness as high severity.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to **security@trustra.ai**
rather than opening a public issue. Include:

- A description of the vulnerability and its impact.
- Steps to reproduce, or a proof of concept if available.
- The affected version or commit.

We aim to acknowledge reports within 3 business days.

## Scope

In scope: the code in this repository. Out of scope: Trustra's hosted
cybersecurity audit product, prediction engine, and knowledge warehouse
content, which are not part of this repository.
