# Guacamole high availability: findings and local experiments

Research date: 14 September 2026. This report evaluates a future deployment option.
It does not extend the approved V1 scope or claim production readiness.

## Recommendation

Two application hosts can serve users at the same time. Each user's requests must
stay with one Guacamole instance. A failed instance requires a fresh sign-in and
remote connection. A shared database does not preserve its application sessions.
The local experiment below checks this distinction.

For automatic database failover, evaluate two PostgreSQL data nodes plus an
independent third voting member. Use a supported failover manager and verified
fencing. With only two machines and no independent arbitration, prefer controlled
manual promotion after fencing the failed primary. PostgreSQL explicitly requires
protection against two primaries and does not supply the failure detector.
[PostgreSQL failover](https://www.postgresql.org/docs/18/warm-standby-failover.html)

A witness protects the election, not the data. Two synchronous data nodes cannot
both require two durable copies and continue writes after either data node fails.
Patroni documents this availability tradeoff and offers strict and non-strict modes.
[Patroni replication modes](https://patroni.readthedocs.io/en/latest/replication_modes.html)

## Existing deployment

The reviewed branch was `codex/entra-browser-signin`, at commit
`6fd77e532e0046044fb8ca9c9799afdc0c19245c`. The deployment template contains one
PostgreSQL container, one Guacamole container, one guacd container, and one NGINX
container. An optional cloudflared container supplies ingress. PostgreSQL and
recordings use host directories. Guacamole reads recordings from a read-only mount.
[Compose template](../../internal/stack/assets/compose.yaml.tmpl)

The template connects Guacamole to the Docker hostname `postgres`. It has no
replication manager, database routing service, cross-host network, or host selection
mechanism. The approved V1 specification supports one deployment per host. Backup
and replacement-host restore belong to V1.
[V1 specification](../v1-specification.md)

A future HA deployment needs its own installation and lifecycle design. In
particular, two installers must not independently own the same Entra application,
Cloudflare hostname, database schema migration, backup schedule, or retention job.
This is an architectural inference from the current local ownership contract.

## Candidate topology

This is a design proposal, not an implemented configuration.

| Location | Components | Failure boundary |
| --- | --- | --- |
| Application host A | Tunnel A, NGINX, Guacamole A, guacd A, local database router, PostgreSQL A, failover manager, voting member A | One host |
| Application host B | Tunnel B, NGINX, Guacamole B, guacd B, local database router, PostgreSQL B, failover manager, voting member B | A different host |
| Independent location C | Third voting member | Separate from both application hosts |
| Shared services | Cloudflare load balancer with affinity, Entra ID, recording storage, independent backups | Each needs explicit availability assumptions |

Both applications use the current writable database primary. PostgreSQL A and B
exchange physical streaming replication. Only one database accepts writes. Each
application normally uses its local guacd. Each surviving host needs capacity for
the full expected workload.

Local database routers avoid a single shared proxy. Their health checks must follow
the failover manager's primary role. A TCP socket check alone cannot distinguish a
primary from a read-only standby. Client reconnect behavior, connection-pool expiry,
and router timing remain untested design requirements.

VMs on one hypervisor do not protect against loss of that hypervisor. The same
applies to a shared power supply, network path, storage array, or upstream firewall.
These are topology deductions, not measured availability results.

## Database behavior and decisions

**Documented:** PostgreSQL supports primary/standby streaming replication. Without
`synchronous_standby_names`, commits do not wait for a standby. Synchronous commits
wait for the configured number of eligible standbys.
[PostgreSQL replication settings](https://www.postgresql.org/docs/18/runtime-config-replication.html)

**Tested locally:** After a standby network disconnection, the primary acknowledged
an insert that the standby did not receive. After fencing the primary and promoting
the standby, that row was absent. The standby did not promote itself before the
explicit promotion command. This demonstrates potential asynchronous data loss.
It does not measure a production recovery time or a maximum loss window.

**Documented:** An etcd cluster needs a majority. Two members need both members.
Three members need two. A third VM on one of the two existing hosts does not survive
loss of that host in all placements. A third independent voting member changes the
failure tolerance. An etcd voter is a full consensus member, not a PostgreSQL replica.
[etcd quorum and failure tolerance](https://etcd.io/docs/v3.6/faq/#why-an-odd-number-of-cluster-members)

**Documented:** Patroni normally stops PostgreSQL after loss of its leader lock.
Process failure or a paused VM can prevent that action. Its watchdog support adds
host reset protection. Actual watchdog behavior and fencing need tests on the
chosen platform. Neither local Docker exercise configured a watchdog or reset a host.
The additional Patroni experiment appears later in this report.
[Patroni watchdog](https://patroni.readthedocs.io/en/latest/watchdog.html)

The data-loss policy needs an explicit choice:

| Policy | Benefit | Cost or limit |
| --- | --- | --- |
| Asynchronous replication | Primary writes continue without the standby | Promotion can lose acknowledged writes |
| Patroni synchronous mode | Restricts automatic promotion to eligible synchronized data | Can keep the primary writable without a standby, then refuse automatic failover |
| Strict synchronous mode | Requires the configured synchronous copy for commits | Loss of the only standby blocks writes |
| Three data nodes with suitable synchronous policy | Can retain a synchronous partner after one data-node failure | Requires a third data host and further failure tests |

These are documented policy properties, not deployment guarantees. Cancellation
while PostgreSQL waits for replication can expose local changes without replication.
Applications must treat interrupted commits as potentially committed.
[Patroni replication modes](https://patroni.readthedocs.io/en/latest/replication_modes.html)

After promotion, the former primary needs rewind or a new base backup before it
returns as a standby. A restart of the old primary is not a safe rejoin procedure.
[PostgreSQL failover and rejoin](https://www.postgresql.org/docs/18/warm-standby-failover.html)

## Guacamole sessions, SAML, and guacd

**Source fact:** Guacamole 1.6.0 stores authentication tokens in a Java
`ConcurrentHashMap`. Its default token map implementation is `HashTokenSessionMap`.
This state lives in the application process.
[Token map source](https://github.com/apache/guacamole-client/blob/1.6.0/guacamole/src/main/java/org/apache/guacamole/rest/auth/HashTokenSessionMap.java),
[default implementation](https://github.com/apache/guacamole-client/blob/1.6.0/guacamole/src/main/java/org/apache/guacamole/rest/auth/TokenSessionMap.java)

**Source fact:** A Guacamole session also owns a map of live tunnels. Session
invalidation closes those tunnels. Tomcat HTTP session replication alone does not
replicate these Guacamole objects or their live network connections.
[GuacamoleSession source](https://github.com/apache/guacamole-client/blob/1.6.0/guacamole/src/main/java/org/apache/guacamole/GuacamoleSession.java)

**Source fact and inference:** The SAML extension keeps pending authentication
attempts through `AuthenticationSessionManager`, which also uses a process-local
map. Affinity must cover the sign-in flow, including the identity-provider callback,
then API calls, WebSocket setup, and HTTP tunnel requests. The Entra browser flow
across two hosts remains untested.
[SAML session manager](https://github.com/apache/guacamole-client/blob/1.6.0/extensions/guacamole-auth-sso/modules/guacamole-auth-sso-saml/src/main/java/org/apache/guacamole/auth/saml/acs/SAMLAuthenticationSessionManager.java),
[authentication session storage](https://github.com/apache/guacamole-client/blob/1.6.0/guacamole-ext/src/main/java/org/apache/guacamole/net/auth/AuthenticationSessionManager.java)

**Source fact:** JDBC active-connection tracking also contains in-memory maps.
Cluster-wide active-session views, administrator disconnect actions, sharing links,
and concurrent-connection limits need targeted validation. A shared database does
not by itself prove cluster-wide enforcement.
[active connection map](https://github.com/apache/guacamole-client/blob/1.6.0/extensions/guacamole-auth-jdbc/modules/guacamole-auth-jdbc-base/src/main/java/org/apache/guacamole/auth/jdbc/tunnel/ActiveConnectionMultimap.java)

**Documented:** guacd handles the remote protocol connection. Guacamole forwards
traffic between the browser and guacd. The proposed pair of local guacd instances
limits a host failure to sessions on that host. Losing the guacd process or its
host does not transfer an existing protocol session to the other guacd.
The transfer conclusion follows from the documented connection architecture.
[Guacamole architecture](https://guacamole.apache.org/doc/gug/guacamole-architecture.html)

A remote Windows desktop can retain its own disconnected session according to its
server policy. This does not preserve the Guacamole browser tunnel. Remote-session
reconnection, recording continuity, and crash cleanup require RDP, SSH, and VNC tests.

The reverse proxy must support WebSocket upgrades and disable buffering for HTTP
tunnels. Affinity must also work when WebSocket falls back to HTTP.
[Guacamole reverse proxy requirements](https://guacamole.apache.org/doc/gug/reverse-proxy.html)

## Cloudflare ingress

**Documented:** Cloudflare does not distinguish replicas of one tunnel UUID as
separate load-balancer endpoints. Host affinity requires separate tunnel UUIDs.
A fixed HTTP status probe proves connector reachability only, not application health.
[Cloudflare tunnel load balancing](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/public-load-balancers/#session-affinity-and-replicas)

The candidate design uses one tunnel per application host and a load balancer with
session affinity. Both origins use the same public SAML entity ID and callback URL.
Monitor the application and its required dependencies. A login-page HTTP 200 cannot
prove database authorization or successful remote connections.

**Documented:** Cloudflare recommends session affinity for WebSocket origins.
WebSocket connections can close during Cloudflare maintenance and idle periods.
Clients need reconnection behavior. Neither origin affinity nor multiple tunnel
connectors promise an uninterrupted browser tunnel.
[Cloudflare WebSockets](https://developers.cloudflare.com/network/websockets/)

Cloudflare plan availability, billing, selected cookie attributes, monitor behavior,
and SAML callback routing were not tested against an account. Verify these before
any customer commitment.

## Recordings and recovery

**Documented:** guacd writes recordings. The web application needs access to the
recording files for playback. Guacamole supports history UUIDs in recording paths.
The current local mount gives only the local application that access.
[recording storage and playback](https://guacamole.apache.org/doc/gug/recording-playback.html)

Two possible storage designs need separate evaluation:

| Design proposal | Benefit | Required validation |
| --- | --- | --- |
| Shared filesystem with its own HA | Both applications can read the same paths | Storage failover, locking, permissions, partial files, capacity, and write failures |
| Local recording spool plus completed-file archive | Recording writes avoid a shared filesystem dependency | Cross-host retrieval, archive delay, host-loss exposure, and retention coordination |

Use history UUID paths to avoid naming collisions. Preserve read-only access for
applications. Define recording loss separately from database loss. Database streaming
replication does not copy recording files. A witness also holds no recording data.
These are consequences of the separate stores.

The V1 specification covers database-aware exports and completed recordings. It
also permits local retention to remove unbacked recordings to enforce the storage
budget. HA does not change that policy without a new decision.
[V1 recording and backup scope](../v1-specification.md)

**Documented:** Point-in-time recovery needs a base backup and the required WAL
archive. A `pg_dump` export cannot serve as that base backup. Database replication
also applies unwanted database changes, so independent recoverable backups remain
necessary.
[PostgreSQL continuous archiving](https://www.postgresql.org/docs/18/continuous-archiving.html)

The HA recovery plan needs off-host encrypted backups, recording manifests, and
recovery keys that survive loss of either VM. Rebuild tests must cover credentials,
configuration, schema, recordings, ingress ownership, and successful sign-in.
Replication, failover, and backup completion need distinct status indicators.

## Local experiment evidence

The disposable harness and results are under
[`.scratch/overnight-20260914/ha/`](../../.scratch/overnight-20260914/ha/).
The harness uses a separate Docker bridge, PostgreSQL data on tmpfs, and application
ports bound to loopback. It has no customer data or external identity provider.
It uses trust authentication only inside this disposable database network. The
random application password and issued tokens remain in process memory.

Docker Desktop was stopped at the start. Starting it restored the `desktop-linux`
context. The environment reported Docker 29.1.3 on aarch64. Image identifiers appear
in `results.json`. These checks are not Rocky Linux or amd64 platform acceptance.

The first two harness attempts found container-startup issues: the image provides
`gosu`, and PostgreSQL requires restrictive data-directory permissions. The third
attempt reached the database checks but could not expose application ports through
its internal-only network. The final harness uses a dedicated normal bridge and
loopback ports. Earlier logs remain as evidence.

The final run passed and exited with code 0. Its source is
[`experiment.py`](../../.scratch/overnight-20260914/ha/experiment.py), with
[`results.json`](evidence/2026-09-14-guacamole-ha/results.json) and
[`experiment.log`](../../.scratch/overnight-20260914/ha/experiment.log).

| Local check | Observed result |
| --- | --- |
| Streaming replica | Standby remained in recovery and received the initial row |
| Asynchronous partition | Primary held two rows while the isolated standby held one |
| Primary stopped | Standby remained in recovery until explicit promotion |
| Promotion after fencing | New primary accepted writes, but lacked acknowledged row 2 |
| Synchronous commit without a standby | Commit remained in `SyncRep` after two seconds |
| Explicit cancellation of that wait | PostgreSQL warned about cancellation, returned success, and exposed the row locally |
| A's token on A, with a shared database | HTTP 200 |
| A's token on B, with the same database | HTTP 403 |
| B's own token on B | HTTP 200 |
| A stopped | A's token still returned 403 on B, while B's own token returned 200 |
| Cleanup | No experiment containers or network remained |

The token checks used database authentication to isolate token locality. They did
not exercise SAML, NGINX, Cloudflare, or a remote desktop. The synchronous check
used explicit cancellation after observing the wait. It did not measure timeout
handling by a Guacamole client. These first checks did not run a failover manager.
The additional experiment below uses Patroni and etcd.

Production acceptance still requires these checks:

1. Lose either whole host, then measure new sign-in and remote-connection recovery.
2. Partition replication, cluster voting, and application access independently.
3. Freeze the primary host, then prove fencing before promotion.
4. Recover and rejoin the former primary without two writable databases.
5. Run SAML callbacks, API calls, WebSocket, and HTTP fallback through both origins.
6. Prove cross-host administration, concurrent limits, and recording playback.
7. Lose storage or fill a recording volume, then inspect session and evidence results.
8. Restore the database and recordings on replacement hosts from independent backups.
9. Drain one application for maintenance and upgrade the shared schema once.

No production recovery-time target, data-loss limit, or uninterrupted-session claim
is established by these local checks.

## Additional Patroni experiment: 15 September, Brisbane

**Tested locally:** A second fixture used two PostgreSQL 18.6 nodes under Patroni
4.1.0 and three etcd 3.6.0 members. All five containers used one internal Docker
network. No ports were published. Trust authentication applied only to the fixture.
No passwords, private keys, customer data, or cloud resources were needed.

The fixture selected asynchronous replication: `synchronous_mode=false` and
`synchronous_commit=on`, with no required synchronous standby. The latter setting
alone does not require a remote copy. Patroni used `ttl=20`, `loop_wait=2`, and
`retry_timeout=3`. DCS failsafe mode and watchdog support were off.
The configuration uses Patroni's documented `bootstrap.dcs` and `etcd3` settings.
[Patroni configuration](https://patroni.readthedocs.io/en/latest/yaml_configuration.html)

| Check | Verified observation |
| --- | --- |
| Initial cluster | All three etcd endpoints passed their health check. One database was primary and one was a replica. |
| Replication | The replica received the first committed row. |
| Abrupt primary-container stop | `docker kill --signal KILL` stopped the primary container. Patroni promoted the other node without a manual promotion command. |
| Promotion timing | The harness observed the new primary after 25.19 seconds. Its timeline changed from 1 to 2. |
| Writes after promotion | The sole running data node accepted a second row. A query returned two rows. |
| Restart of the stopped container | Its tmpfs data was empty. Patroni rebuilt it as a replica of the new primary. |
| Loss of two etcd voters | After a 45-second sampling period, both databases reported replica status. The remaining etcd endpoint failed its health check. |
| Writes without quorum | Both databases rejected inserts with a read-only transaction error. |
| Former primary stopped without quorum | The surviving replica did not promote in 15 observations across a further 30 seconds. |

The promotion timing is one observation on Docker Desktop/aarch64. It includes
local polling and container-command overhead. It is not an application recovery-time
guarantee. The test waited for the first row to replicate before stopping the
primary. It does not establish a zero-loss guarantee for asynchronous replication.

The restart test proves reconstruction from the surviving database into empty
storage. It does not test rewind or reconciliation of a former primary's retained
data. The fixture also did not exercise Guacamole database routing or connection
pool recovery.

Stopping a Docker container kills the database and its manager together. This does
not reproduce a frozen host or a failed Patroni process with PostgreSQL still alive.
The experiment provides no proof of watchdog fencing, protection from split brain,
or availability across physical failure domains. It also does not test asymmetric
network partitions or quorum restoration. These remain deployment acceptance work.

The fixture source, Dockerfile, image identifiers, and structured observations are
under [`patroni/`](evidence/2026-09-14-guacamole-ha/patroni/). The source generates
the non-secret configuration. Local scratch files retain the container logs.

The harness completed with exit code 0 at 00:22 Brisbane. Cleanup removed all five
containers, their anonymous volumes, the fixture network, and both added image tags.
The final container and network queries returned empty output. Both image inspections
returned “No such image”. The exact commands and results appear in
[`cleanup.json`](evidence/2026-09-14-guacamole-ha/patroni/cleanup.json).
No shared Docker cache or pre-existing image was removed.
