# audit

audit keeps the immutable record of human actions. It consumes the
`ALL_AUDIT` JetStream stream through the durable consumer `audit`
(filter `*.audit.*.sub`, explicit acknowledgement), stores each message once
by `(publisher, publisher_seq)` in its own PostgreSQL schema, and answers
team-filtered reads for API Gateway on `audit.ui.list.sub` and
`audit.ui.get.sub` (queue group `audit`). It publishes no stream message.

## Layout

| Path                   | Content                                                                                   |
| ---------------------- | ----------------------------------------------------------------------------------------- |
| `cmd/audit/`           | the binary: `audit --config /etc/flowai/config.yaml`                                      |
| `internal/audit/`      | consumer (validation, dedupe, rejection) and reads (context, params, cursors, replies)    |
| `internal/store/`      | PostgreSQL store; one advisory lock serializes stores so `audit_id` order is commit order |
| `internal/migrations/` | SQL migrations; objects only in the configured schema                                     |
| `internal/broker/`     | NATS connection, durable-consumer fetcher, request subscriptions, consumer loop           |
| `internal/cursor/`     | HMAC-signed list cursors bound to operation, team, operator, search and order             |
| `internal/config/`     | YAML configuration; refuses to start without production trust                             |
| `internal/health/`     | `/v1/livez` and `/v1/readyz`, the only HTTP routes                                        |
| `internal/app/`        | wiring used by `main` and by the tests                                                    |
| `internal/mocks/`      | in-process fakes for unit tests only                                                      |
| `schemas/`             | reply and request JSON Schemas, `consumers.json`                                          |
| `test/`                | unit tests; integration tests (`//go:build integration`) against PostgreSQL               |

## Consumer

A message on `<publisher>.audit.<action>.sub` must carry `publisher` equal
to the subject's first token, a positive `publisher_seq`, and the audit field
set. The NATS header `team` is the trusted team: a decimal team for an
operator message (`actor_type: operator`, `actor_id`, `team_id`) or `admin`
for an administrator message (`actor_type: administrator`, `actor_subject`;
stored without a team).

| Message                                                | Result                                                                                          |
| ------------------------------------------------------ | ----------------------------------------------------------------------------------------------- |
| valid, new pair                                        | stored with the next `audit_id`, then acknowledged                                              |
| pair already stored or rejected                        | acknowledged, nothing stored                                                                    |
| payload `team_id` differs from the `team` header       | pair recorded as rejected, acknowledged, nothing stored                                         |
| malformed (wrong subject, header, type, missing field) | terminated (`+TERM`), stored nowhere; the log names only publisher, `publisher_seq` and subject |
| database unavailable                                   | not acknowledged; JetStream redelivers it                                                       |

`resource_id` must be present and is a positive integer or `null`.
`source_service` is taken from the subject. Unknown fields and `reason` are
dropped; `changes` (an object of display values) is kept.

## Reads

Request headers `team`, `operator_id`, `request_id` (decimal) and an
optional `team_name`, which never authorizes. Body `{"params": {...}}`.

- `audit.ui.list`: `team_id` (must equal the header), optional `search`
  (case-insensitive substring of action, actor_id or resource_id), `cursor`,
  `limit` (10, 25, 50 or 100; default 10). Order `occurred_at DESC,
audit_id DESC`. Reply `{"items": [...], "next_cursor": string|null}`.
- `audit.ui.get`: `team_id`, `audit_id` (JSON number). An unknown, foreign or
  administrator entry gets the same `404 resource_not_found`.

Replies carry the NATS header `status`. Errors are
`{code, message, request_id}` with `invalid_request`, `invalid_pagination`,
`resource_not_found` or `service_unavailable`.

## Configuration

`config.example.yaml` lists every key. PostgreSQL needs `sslmode:
verify-full` and a CA file. NATS needs a `tls://` URL, a CA file and a user
credentials file. The schema is pre-created by the deployment; the
migration creates it only when it is missing.

## Tests

```sh
export FLOWAI_CONTRACT_FIXTURE_DIR=/absolute/path/to/contract-fixtures
go test -mod=readonly -count=1 ./...
go test -mod=readonly -count=1 -tags=integration ./...
```

The committed qualification manifests record which schemas the Gitea
selector declares for Audit and the SHA-256 of each reviewed schema body.
The workflow stages verified schema bodies under their original
`svc/<publisher>/schemas/` paths in `FLOWAI_CONTRACT_FIXTURE_DIR`.
The schema bodies stay outside the repository and build context.

The dispatch workflow validates the selected Audit revision, stages the
publisher contracts, runs the owned suites, checks teardown and builds an
untagged Linux image. Integration uses pinned, disposable PostgreSQL via
Docker or Podman.
