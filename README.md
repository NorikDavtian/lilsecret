# lilsecret

<img width="816" height="691" alt="image" src="https://github.com/user-attachments/assets/30d32437-8590-4524-8d31-fcc06e89b278" />


🤫 burner notes — read once, then gone.

Encrypted one-time note sharing. The sender seals notes in the browser and
gets a single-use link plus a one-time code (or their own passphrase). The
recipient needs both to read the notes — one read, three wrong codes, or an
expired shelf life, and the drop erases itself. No accounts, no analytics.

Runs as a single zero-dependency Node server (static frontend + JSON API +
SQLite) with a self-contained deployment to a DigitalOcean Kubernetes
cluster: own namespace, kustomize manifests, nginx-ingress, cert-manager
TLS, and a small persistent volume for the (sealed) database.

## How the sealing works
<img width="810" height="660" alt="image" src="https://github.com/user-attachments/assets/eca78866-39bb-4f16-8483-a50beb0a4822" />
<img width="811" height="767" alt="image" src="https://github.com/user-attachments/assets/37971611-610c-4783-a212-11c470d4cf7b" />
<img width="806" height="682" alt="image" src="https://github.com/user-attachments/assets/e5ee6b04-3342-4508-8697-c61095f37b1d" />


- Notes are encrypted **on the sender's device** with AES-256-GCM. The key
  is derived (PBKDF2-SHA256 · 310k iterations, then HKDF) from **two**
  inputs: the code/passphrase, and a random link-key that travels only in
  the URL fragment (`#…`) — browsers never send fragments to servers.
- The server stores ciphertext, the KDF salt/iv, a **hash of a verifier**
  (a second PBKDF2 output), and the burn policy. It can referee wrong-code
  attempts without being able to decrypt anything. A database leak alone
  can't decrypt a drop — even by brute-forcing every 6-digit code — because
  the link-key half never reaches the server. The link alone faces the
  3-attempt limit, then the drop self-destructs.
- On a successful unlock the payload leaves the server exactly once and is
  wiped immediately; what remains is a tombstone that only says *how* the
  drop ended (read, self-destructed, expired, burned by hand).
- Every stored record is sealed **again** server-side (AES-256-GCM with
  `STORAGE_KEY`) before touching SQLite, so a leaked volume snapshot reveals
  nothing — the key lives in a Kubernetes Secret, not on the volume.
- Notes are plain text end to end — the app renders decrypted content only
  via `textContent` (no HTML injection surface at all).

## Run locally

```bash
node server.js --port 8789
```

Data lands in `./data` (gitignored) with a generated dev storage key.
Docker: `docker build -t lilsecret . && docker run --rm -p 8080:8080 lilsecret`

## Make it yours

Deployment-specific values never live in commits:

- Copy `.env.example` to `.env` (gitignored) and set your container
  registry — and optionally your cluster name.
- Set your hostname in `manifests/ingress.yml` and your contact email in
  `manifests/ssl.yml`.
- The image reference in the manifests is a placeholder; the deploy
  pipeline points it at your registry with kustomize at apply time.
- The at-rest `STORAGE_KEY` Secret is cut automatically on first deploy.

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
pushes it to your registry, ensures the namespace + secrets exist, applies
`manifests/` with kustomize, and waits for the rollout.

Not on DigitalOcean, or don't want any of this? The whole app is one
Docker image with zero dependencies — just tell your LLM "deploy this
Docker image to my infra" and let it adapt the manifests. The only things
it needs to know: the container listens on 8080, wants a `STORAGE_KEY`
secret (64 hex chars), and keeps its SQLite file in `/data` (mount a small
volume there).
