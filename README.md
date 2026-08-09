# lilsecret

🤫 shh… something small is brewing.

A tiny static page served by nginx, with a fully self-contained deployment
to a DigitalOcean Kubernetes cluster: its own namespace, kustomize
manifests, nginx-ingress routing, and cert-manager TLS. Small enough to
read in one sitting — useful as a template for deploying any containerized
app to its own namespace on an existing cluster.

## Run locally

```bash
docker build -t lilsecret . && docker run --rm -p 8080:80 lilsecret
```

Then open http://localhost:8080.

## Make it yours

Deployment-specific values never live in commits:

- Copy `.env.example` to `.env` (gitignored) and set your container
  registry — and optionally your cluster name.
- Set your hostname in `manifests/ingress.yml` and your contact email in
  `manifests/ssl.yml`.
- The image reference in the manifests is a placeholder; the deploy
  pipeline points it at your registry with kustomize at apply time.

Assumes the cluster already runs an nginx ingress controller and
cert-manager, and that DNS for your hostname points at the cluster's load
balancer.

## Deploy

Locally (Docker running, `doctl` authenticated):

```bash
./deploy.sh
```

Via GitHub Actions: add repo secrets `DIGITALOCEAN_ACCESS_TOKEN`,
`DO_CLUSTER_NAME`, and `DO_REGISTRY`, then:

```bash
gh workflow run deploy.yml
```

Either path builds a `linux/amd64` image tagged with the short git SHA,
pushes it to your registry, creates the registry pull secret in the app
namespace, applies `manifests/` with kustomize, and waits for the rollout.
TLS issues automatically on first deploy via the HTTP-01 challenge.
