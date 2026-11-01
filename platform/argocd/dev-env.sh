#!/usr/bin/env bash
# Deploy (or remove) a Dev environment for one Hanoi feature branch.
#   ./dev-env.sh feature/CCBD-1234          -> namespace dev-ccbd-1234, all charts
#   ./dev-env.sh feature/CCBD-1234 --delete
set -euo pipefail
BR="${1:?usage: dev-env.sh feature/<JIRA-ID> [--delete]}"
[[ "$BR" =~ ^feature/[A-Z][A-Z0-9]+-[0-9]+$ ]] || { echo "Expected feature/<JIRA-ID>"; exit 1; }
ID="${BR#feature/}"; NS="dev-${ID,,}"
REPO="https://github.com/NiveshRamesh/hanoi.git"

if [[ "${2:-}" == "--delete" ]]; then
  kubectl -n argocd delete applicationset "$NS" --ignore-not-found
  kubectl delete namespace "$NS" --ignore-not-found
  exit 0
fi

kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: ${NS}
  labels:
    env: dev
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/warn: restricted
---
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: ${NS}
  namespace: argocd
spec:
  goTemplate: true
  generators:
    - git:
        repoURL: ${REPO}
        revision: ${BR}
        directories:
          - path: helm-charts/*
  template:
    metadata:
      name: "${NS}-{{.path.basename}}"
    spec:
      project: default
      source:
        repoURL: ${REPO}
        targetRevision: ${BR}
        path: "{{.path.path}}"
        helm:
          releaseName: "{{.path.basename}}"
      destination:
        server: https://kubernetes.default.svc
        namespace: ${NS}
      syncPolicy:
        automated: { prune: true, selfHeal: true }
EOF
echo "Dev environment ${NS} now tracks Hanoi ${BR}"
