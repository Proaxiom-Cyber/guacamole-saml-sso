# Guacamole clustering: upstream reports and implementation risks

Research date: 15 September 2026. Target: Guacamole 1.6.0, three full nodes,
shared PostgreSQL primary and replicas, Patroni/etcd, and Cloudflare ingress.
This research used upstream documentation, tagged source, maintainer replies,
and first-party operator reports. It did not change infrastructure or reproduce
the reported bugs.

## Main finding

Multiple Guacamole application instances can share a database. That does not
create shared application sessions. The first HA release needs session affinity,
one local guacd per application instance, and explicit limits on cluster-wide
administration and screen sharing.

In November 2025, maintainer Nick Couchman confirmed this deployment pattern.
He recommended a persistent one-to-one relationship between Guacamole and guacd.
He warned that application instances do not share active connection information.
His examples include unreliable sharing links, multiplied concurrency limits,
and authentication or connection errors when requests change application nodes.
This is direct maintainer guidance, rather than an inference from a third-party
installation guide. [Maintainer response, 6 November 2025](https://www.mail-archive.com/user%40guacamole.apache.org/msg14891.html)

## Findings and required tests

### 1. Shared PostgreSQL does not share authentication tokens

The tagged 1.6.0 `HashTokenSessionMap` stores token-to-session mappings in a Java
`ConcurrentHashMap`. There is no database lookup in its `get()` method. Its
shutdown method invalidates the sessions in that local map.
[Guacamole 1.6.0 token map](https://github.com/apache/guacamole-client/blob/1.6.0/guacamole/src/main/java/org/apache/guacamole/rest/auth/HashTokenSessionMap.java)

**Implementation requirement:** keep authenticated HTTP requests and the tunnel
on the assigned application node. A healthy replacement node does not recognize
the old node's token. Node failure can require a fresh application login as well
as a desktop reconnection. Entra SSO might make that login quick, but does not
replicate the Guacamole token.

**Test:** authenticate through node A, send that token to B, then fail A through
the real ingress. Check that the UI recovers through authentication without a
redirect loop or repeated attempts with the invalid token.

### 2. SAML needs affinity during authentication, too

Guacamole 1.6.0 stores temporary authentication sessions in memory through
`AuthenticationSessionManager`. `SAMLAuthenticationSessionManager` inherits that
storage. The assertion callback accepts an HTTP POST, stores the asserted identity
in this local manager, then redirects the browser to finish authentication.
[Authentication session storage](https://github.com/apache/guacamole-client/blob/1.6.0/guacamole-ext/src/main/java/org/apache/guacamole/net/auth/AuthenticationSessionManager.java),
[SAML session manager](https://github.com/apache/guacamole-client/blob/1.6.0/extensions/guacamole-auth-sso/modules/guacamole-auth-sso-saml/src/main/java/org/apache/guacamole/auth/saml/acs/SAMLAuthenticationSessionManager.java),
[Assertion callback](https://github.com/apache/guacamole-client/blob/1.6.0/extensions/guacamole-auth-sso/modules/guacamole-auth-sso-saml/src/main/java/org/apache/guacamole/auth/saml/acs/AssertionConsumerServiceResource.java)

**Inference for our deployment:** a successful Entra sign-in can still fail when
the callback or following request reaches a different application instance.
Affinity limited to the WebSocket path is insufficient. Test the complete browser
journey, including cross-site POST cookie behavior, through Cloudflare.

**Test:** new browser session, normal SAML login, delayed MFA, repeated login,
callback after a node failure, and affinity-cookie expiration. Log only node IDs
and outcomes. Do not capture SAML assertions or bearer tokens.

### 3. Concurrency limits are not cluster-wide limits

An April 2024 maintainer response gives a specific example: a limit of ten on each
of three application instances can permit thirty connections. The response also
warns that a sharing link can reach a node without the corresponding connection.
[Maintainer response, 8 April 2024](https://www.mail-archive.com/user%40guacamole.apache.org/msg12982.html)

The older HA feature request reports this problem with three Guacamole 0.9.12
servers behind HAProxy. It remains Open and Unresolved, with no fix version at
the research date. It is historical evidence, not proof that every original
symptom affects our release. The later maintainer replies establish continuing
relevance. [GUACAMOLE-283](https://issues.apache.org/jira/browse/GUACAMOLE-283)

**Implementation requirement:** do not describe configured limits as a global
cluster cap. A per-node cap divided by three is not an exact substitute under
uneven load or failure. Either document per-node limits or implement separate
coordination if a customer requires strict global enforcement.

**Test:** hold connections open through A, then establish connections through B
and C. Check per-user and group limits. Confirm the operator UI explains their
scope.

### 4. Active-session administration and sharing need separate treatment

Maintainers distinguish routing to the correct application from routing to the
correct guacd. A shared desktop exists in a particular guacd process. Their
documented working patterns include application/guacd pairs behind sticky ingress
when screen sharing is not required. Preserving sharing needs routing that knows
the owning instance or a custom extension.
[Maintainer explanation, 13 January 2018](https://www.mail-archive.com/user%40guacamole.apache.org/msg00371.html)

**Inference:** an administrator on B must not assume the Active Sessions screen
contains A's sessions or can terminate them. A cluster status command can report
node health without pretending to aggregate Guacamole's administrative API.

**Test:** open a desktop through A; view and terminate it from administrator
sessions assigned to A and B. Test a sharing link in a separate browser. The
first release must either support owner-aware routing or declare these actions
node-scoped. Basic per-user stickiness does not place two different users on
the same node.

### 5. There are current disconnect and proxy reports worth reproducing

**GUACAMOLE-2293:** a July 2026 operator report affects the official 1.6.0 image
with JDBC/MySQL, LDAP/TOTP, Podman, and a Cloudflare tunnel. The reporter describes
concurrent disconnects leaving ghost active sessions that consume limits. An
administrator's termination request can return success without clearing them.
The report attributes this to socket-close cleanup races. Jira remains Open,
with no fix version. The patch is also open; maintainer review asks whether other
cleanup paths need the same treatment. We have not reproduced it with our
PostgreSQL/Docker stack. [GUACAMOLE-2293](https://issues.apache.org/jira/browse/GUACAMOLE-2293),
[upstream PR 1223](https://github.com/apache/guacamole-client/pull/1223)

**Test:** several concurrent RDP sessions, simultaneous tab closure, tunnel
interruption, and guacd termination. Confirm sessions and concurrency seats
clear. Compare the administrative result with actual guacd processes. Do not
patch upstream code solely because an unmerged patch exists.

A March 2026 operator reported errors for roughly 10–15% of users in an ECS
deployment. It used sticky application balancing and separate guacd tasks behind
a network load balancer. The post does not establish a cause, and this research
did not locate a diagnostic reply. Treat it as a test lead, not a measured failure
rate for our design. [Scaling Apache Guacamole](https://www.mail-archive.com/user%40guacamole.apache.org/msg15131.html)

A 2019 maintainer reply explains another failure pattern: a partly working
WebSocket proxy can establish a connection, then trigger HTTP fallback that
collides with concurrency limits. Raising the limit hides the symptom.
[WebSocket and concurrency diagnosis](https://www.mail-archive.com/user%40guacamole.apache.org/msg03807.html)

**Design choice:** retain one local guacd per application node. Test real
WebSocket traffic, idle sessions, and HTTP fallback through every proxy layer.

### 6. Recordings need storage outside the database

The 1.6.0 playback extension searches files on disk, associated with history UUIDs.
guacd needs write access; the application container needs read access. Container
UIDs, GIDs, and volume mounts matter. A common database does not provide those
files to another host.
[Guacamole 1.6.0 recording storage](https://guacamole.apache.org/doc/1.6.0/gug/recording-playback.html)

An operator reported missing playback with recording storage mounted only in
guacd. The maintainer response requires the application to access the same files.
[Recording mount report](https://www.mail-archive.com/user%40guacamole.apache.org/msg11839.html)

**Implementation requirement:** decide whether HA provides shared live playback,
or local recording plus remote archival and explicit retrieval. The current Azure
backup destination alone does not implement Guacamole's filesystem playback.
Shared storage also needs its own failure policy and availability design.

**Test:** record through A and play through B; fail A; repeat playback. Test a
missing mount, storage outage, permission mismatch, and retention while another
node writes an active recording. Do not let multiple cleanup jobs delete shared
active files using only local process information.

## Proposals are not shipped features

GUACAMOLE-2199 proposes a proxy-supplied base URL to route users to an application
node. At the research date it is Open, affects 1.6.0, and has no fix version.
Do not depend on `auth-base-url-header` as a supported 1.6.0 property.
[GUACAMOLE-2199](https://issues.apache.org/jira/browse/GUACAMOLE-2199)

Guacamole connection-group balancing selects remote desktops. It is a separate
feature from balancing Guacamole application instances. Its failover-only
connection feature does not provide application clustering.
[GUACAMOLE-317](https://issues.apache.org/jira/browse/GUACAMOLE-317)

## Cloudflare integration checks

Cloudflare's default affinity cookie can use `SameSite=Lax` when Always Use HTTPS
is enabled. The API supports explicit `samesite: None` and `secure: Always`.
Our SAML callback accepts a cross-site POST. **Inference:** default cookie behavior
can interrupt affinity at that step. Set and test the cookie attributes with real
Entra authentication instead of relying on a successful command-line HTTP probe.
[Cloudflare cookie configuration](https://developers.cloudflare.com/waf/troubleshooting/samesite-cookie-interaction/)

Cloudflare documents distinct tunnels for load-balanced replicas and a
connector-level static response for basic health checks. The production monitor
must also detect application, guacd, and database failures. A reachable connector
does not prove the node can establish a desktop connection.
[Public load balancers and tunnels](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/public-load-balancers/)

Cloudflare also documents WebSocket termination during edge software restarts.
Test reconnect behavior without assuming that every disconnect signals a failed
cluster node. [Cloudflare WebSockets](https://developers.cloudflare.com/network/websockets/)

## Decision for the proposed HA mode

Proceed with three nodes and local application/guacd pairs. Keep PostgreSQL HA
as a separate subsystem. Before promising application HA, prove the browser
affinity path, failure recovery, node-scoped administration, recording behavior,
and disconnect cleanup. Shared database configuration alone does not satisfy
those acceptance criteria.

Three full database and voting members remain a useful design regardless of the
application routing choice. **Alternative proposal:** use one active application
pair and standby pairs if customers need one current view of sessions and limits.
That reduces normal-operation ambiguity but still loses local session state on
failover. Active/active applications require accepting or resolving the listed
limitations. Neither alternative changes PostgreSQL into a multi-writer database.
