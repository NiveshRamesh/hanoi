# hanoi

GitOps repository: Helm charts for every service plus the record of which image tag each
environment runs. **A service repository is what we build; Hanoi is what we deploy.**

```
hanoi/
|-- helm-charts/<service>/          Chart.yaml (appVersion) + values.yaml (imageTag, written by CI)
|-- platform/
|   |-- argocd/                     ApplicationSets: smoke <- develop, qa <- release/x.y, dev-env.sh for feature/*
|   |-- kyverno/policies.yaml       admission: signed-by-central-pipeline, allowed registry, no :latest
|   `-- cluster/                    namespaces (Pod Security "restricted") + setup-kind.sh
`-- .github/
    |-- release-repos.txt           service repos that are part of a release
    `-- workflows/
        |-- release.yaml            "Propagate release branches" (manual)
        |-- release-bundle.yaml     "Run bundle (manual)": precheck + package + GitHub release
        |-- helm-checks.yaml        helm lint, kubeconform, Trivy config, manual-tag guard
        `-- nightly-image-rescan.yaml  re-scans deployed images for new CVEs
```

| Hanoi branch | Updated by | Deployed to |
|---|---|---|
| `feature/<JIRA-ID>` | feature builds (branch auto-created from `develop`) | `dev-<jira-id>` namespace |
| `develop` | merges to service `develop` | `smoke` namespace |
| `release/<x.y>` | release builds (branch made by `release.yaml`) | `qa` namespace |

Rules:
- Never edit `imageTag` / `imageName` / `appVersion` by hand. PRs that do are blocked.
- Helm template changes go through a normal PR to `develop`.
- Feature branches here are never merged into `develop` automatically.
