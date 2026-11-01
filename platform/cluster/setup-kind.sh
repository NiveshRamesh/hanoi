#!/usr/bin/env bash
# Local stand-in for the org's Dev / Smoke / QA clusters: ONE kind cluster with
# namespaces dev-<jira>, smoke and qa, Argo CD (GitOps from Hanoi) and Kyverno.
# Needs: docker, kind, kubectl, helm.  Run from the hanoi repo root.
set -euo pipefail

CLUSTER="${CLUSTER:-devsecops}"
ARGOCD_VERSION="${ARGOCD_VERSION:-v3.5.6}"
KYVERNO_CHART_VERSION="${KYVERNO_CHART_VERSION:-3.9.2}"

for t in docker kind kubectl helm; do command -v "$t" >/dev/null || { echo "Missing $t"; exit 1; }; done

kind get clusters | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER"
kubectl config use-context "kind-$CLUSTER"

echo ">> Argo CD $ARGOCD_VERSION"
kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -n argocd --server-side --force-conflicts \
  -f "https://raw.githubusercontent.com/argoproj/argo-cd/${ARGOCD_VERSION}/manifests/install.yaml"

echo ">> Kyverno chart $KYVERNO_CHART_VERSION"
helm repo add kyverno https://kyverno.github.io/kyverno/ >/dev/null
helm repo update kyverno >/dev/null
helm upgrade --install kyverno kyverno/kyverno -n kyverno --create-namespace \
  --version "$KYVERNO_CHART_VERSION" --wait

echo ">> Namespaces (Pod Security 'restricted') and admission policies"
kubectl apply -f platform/cluster/namespaces.yaml
kubectl apply -f platform/kyverno/policies.yaml

echo ">> Waiting for Argo CD"
kubectl -n argocd rollout status deploy/argocd-applicationset-controller --timeout=300s
kubectl -n argocd rollout status deploy/argocd-repo-server --timeout=300s

echo ">> GitOps: smoke <- hanoi develop"
kubectl apply -f platform/argocd/smoke-appset.yaml
echo "   (apply platform/argocd/qa-appset.yaml after the first release branch exists)"

cat <<EOF

Done.
  Argo CD UI : kubectl -n argocd port-forward svc/argocd-server 8443:443  -> https://localhost:8443
  Password   : kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d
  Smoke apps : kubectl -n smoke get pods
  Dev env    : platform/argocd/dev-env.sh feature/<JIRA-ID>
EOF
