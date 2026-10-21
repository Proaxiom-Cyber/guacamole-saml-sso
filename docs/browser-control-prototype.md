# Browser control prototype

Branch: `codex/browser-control-prototype`.

This local prototype tests pairing a terminal with a browser. It runs a simulated
setup. It cannot change deployments, call cloud APIs, read credentials, or run
shell commands. It is separate from the existing Cloudflare sign-in service.

## Try it

From the repository, start the relay in one terminal:

```sh
go run ./cmd/guacdeploy-web-preview --mode serve --relay http://127.0.0.1:18876
```

Start the agent in a second terminal:

```sh
go run ./cmd/guacdeploy-web-preview --mode agent --relay http://127.0.0.1:18876
```

1. Open <http://127.0.0.1:18876> on this computer.
2. Enter the code displayed by the agent.
3. Type `PAIR` in the agent terminal to approve this browser session.
4. Review a plan for `access.example.com` and request the simulation.
5. Type that hostname in the terminal to approve the exact plan.
6. Watch the simulated progress. Select **Disconnect session** to end access.

Press Ctrl+C in each terminal to stop the preview. Restart the agent if its
five-minute pairing code expires. Session credentials stay in memory.

## Boundaries tested

- A code can be used once. Pairing requires terminal confirmation.
- Unpaired sessions expire after five minutes; approved sessions after 30 minutes.
- Browser and agent credentials are separate and restricted to one session.
- Browser writes require the expected origin. The relay validates the Host header.
- The browser cookie is HttpOnly and SameSite Strict. HTTP is allowed only on
  loopback for this preview. A hosted service must use HTTPS and Secure cookies.
- The agent validates the action, hostname, plan digest, and command identifier.
- Only the built-in simulation is allowed. A changed or repeated command fails.
- Progress must arrive in order. Disconnect prevents subsequent progress.
- Request sizes, pairing attempts, and concurrent sessions have limits.
- The agent makes outbound requests only. It does not open a listening port.

Run `go test -race ./internal/webpreview` for authorization, expiry, isolation,
replay, input validation, and the end-to-end agent simulation tests.

## Before a hosted version

Customer administrators are in scope. Do not restrict sign-in to Proaxiom staff.
Verified identity alone must not grant deployment access. Pairing must bind the
verified administrator, customer, terminal, and session. Show that identity and
session scope in the terminal before approval.

Administrator sign-in is not implemented here. Public hosting is deliberately
blocked by the executable. A production design still needs identity validation,
customer isolation, protection against pairing phishing, secure session renewal,
revocation, audit records, and service abuse limits.

Real deployment actions need a narrow command interface and local authorization.
Do not add a remote shell or forward arbitrary terminal input. Keep credentials
at the deployment agent. Define recovery for interrupted actions before enabling
resource changes. Review relay compromise and browser compromise explicitly.

The final hosted design must work with a browser on a separate device. No browser
or inbound connection should be required on the deployment server. This local
preview tests the interaction and protocol, not that hosted network path.
