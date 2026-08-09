#!/usr/bin/env bash
# Local deploy — mirrors .github/workflows/deploy.yml. Needs Docker running
# and doctl authenticated. Copy .env.example to .env first: all
# deployment-specific values live there, never in commits.
set -euo pipefail
cd "$(dirname "$0")"

[ -f .env ] && . ./.env
: "${DO_REGISTRY:?set DO_REGISTRY in .env (see .env.example)}"

IMAGE=lilsecret
NAMESPACE=lilsecret
SHA=$(git rev-parse --short HEAD)

doctl registry login
# Most managed clusters run amd64 nodes — pin the platform so a build from
# an ARM machine can't produce images that CrashLoop with "exec format error".
docker build --platform linux/amd64 -t "$DO_REGISTRY/$IMAGE:$SHA" .
docker push "$DO_REGISTRY/$IMAGE:$SHA"

if [ -n "${DO_CLUSTER_NAME:-}" ]; then
  doctl kubernetes cluster kubeconfig save "$DO_CLUSTER_NAME"
fi

# Namespace must exist before the registry pull secret can land in it.
# doctl names the secret registry-<registry-name>.
kubectl apply -f manifests/namespace.yml

# At-rest storage key: cut once, lives only as a Secret — never on the data
# volume it protects, never in the repo.
if ! kubectl get secret lilsecret-storage -n "$NAMESPACE" >/dev/null 2>&1; then
  kubectl create secret generic lilsecret-storage -n "$NAMESPACE" \
    --from-literal=STORAGE_KEY="$(openssl rand -hex 32)"
fi
doctl registry kubernetes-manifest --namespace "$NAMESPACE" | kubectl apply -f -
kubectl patch serviceaccount default -n "$NAMESPACE" \
  -p "{\"imagePullSecrets\": [{\"name\": \"registry-${DO_REGISTRY##*/}\"}]}"

cd manifests
kustomize edit set image "lilsecret=$DO_REGISTRY/$IMAGE:$SHA"
kubectl apply -k .
# Restore the placeholder so the real registry never lands in a commit.
git checkout -- kustomization.yml
cd ..

kubectl rollout status deployment/lilsecret-deployment -n "$NAMESPACE" --timeout=180s
echo "Deployed lilsecret at $SHA"
