# busystack_graph

Pure Dart Microsoft Graph request infrastructure, extracted from the inspected BusyBox request pipeline and informed by BusyMax. Public API: `package:busystack_graph/busystack_graph.dart`. No application, Flutter, OAuth browser, account database or mail/calendar DTO dependencies.

`GraphClient` accepts an application-owned `GraphTokenProvider`, HTTP client, cancellation token, budget/accounting callbacks and explicit resource headers. `GraphAuthorization` carries the token and actual granted scopes. `GraphResponse` exposes bounded bytes and synchronous or isolate-based JSON decoding. `GraphException` carries safe error categories, correlation IDs, claims challenges and Retry-After information.

Graph destinations and opaque next/delta links are validated before authorization. HTTPS global Graph v1.0 is the supported endpoint. Redirects are disabled. The application explicitly supplies `Prefer: IdType="ImmutableId"` for Outlook resources; no calendar timezone is imposed on contacts. `GraphUploadDestination` is an exact preauthorized HTTPS capability URL, used by `upload` without the Graph bearer token. It does not authorize a family of arbitrary upload hosts.

`download` and `upload` stream with backpressure, separate from JSON response limits. Download range responses are checked. Dispatched mutation timeouts, cancellations and inconclusive failures produce `unknownOutcome`; a caller must reconcile before retrying. This transport performs no transport/backoff retries. The contacts synchronization layer owns bounded read retries; future mail/calendar consumers retain their application retry policy.

A complete Graph HTTP 401 Bearer `insufficient_claims` challenge is decoded from its documented base64 representation into bounded JSON claims, passed through the same account's token provider, and replayed once with the new token. Buffered request bytes and resource headers are preserved; streaming downloads replay only before yielding response data. Repeated or malformed challenges stop the flow. Streaming/preauthorized uploads never participate in claims replay. The token provider receives JSON for MSAL and retains ownership of its registered authority, account identity, refresh and any required interaction; the header's authorization URI never redirects token acquisition.

Run with Dart 3.13.4 or later:

```
dart pub get --enforce-lockfile
dart format --output=none --set-exit-if-changed lib test example
dart analyze
dart test
dart run example/main.dart
```

The example uses a deterministic HTTP fixture and imports only public libraries. Package contract tests cover endpoint and credential isolation, immutable headers, cancellation, response bounds, streaming/backpressure, correlation/claims/throttling and uncertain uploads. See the sibling BusyCards implementation report for measured streaming memory and exact command results. BusyBox and BusyMax have not adopted this package in Milestone 1.

Local release layout uses this package beside BusyCards and busystack_contacts. A future externally published release can replace the consumer's relative path dependency with an exact hosted version of this same package; no new package hierarchy is required. Publication is not performed here. Apache-2.0; see LICENSE and NOTICE.
