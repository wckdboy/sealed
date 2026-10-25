# ADR 0007 — SQLite (WAL) now, Postgres-shaped schema

**Status:** accepted
**Date:** 2026-10-25

## Context

The plan specifies PostgreSQL + Redis on a CX22 (2 vCPU, 4 GB). For phase 0/1 —
one writer, thousands of accounts, blobs on disk — SQLite in WAL mode on the same
box is faster to operate, has no network hop, no vacuum surprises at this size,
and makes the whole service a single binary plus a directory.

The risk of choosing SQLite is a schema that only works on SQLite, making the
planned move to Postgres a rewrite. That risk is controlled here, not accepted
blindly.

## Decision

- SQLite with `journal_mode=WAL`, `synchronous=NORMAL`, `foreign_keys=ON`,
  `busy_timeout=5s`, max 8 pooled connections.
- Schema is written for portability: no SQLite-only types, no triggers, no
  `AUTOINCREMENT` semantics the application depends on, all timestamps are
  INTEGER unix seconds, all ids are TEXT, all booleans are INTEGER 0/1 (Postgres:
  `boolean`), no JSON columns.
- Redis is **not** used: sessions are rows in `sessions` (hashed tokens), and
  there is no chat yet. When chat lands (phase 2) it gets its own store, because a
  pub/sub write path does not belong in the same database as billing.
- Migration path: swap `db::connect` for a `sqlx::PgPool`, run the same DDL with
  types translated, and keep blobs where they are (they are files, not rows).

## Consequences

- Writers serialize. At this design that is one row per upload and one per view
  count; measured locally at >2k writes/s in-process, far above projected load.
- Backups are `sqlite3 .backup` (or a file copy while stopped) plus the blob
  directory; both are ciphertext or non-secret metadata.
- If a second API node is ever needed, that is the trigger to move to Postgres.
  Do not shard SQLite over NFS — that fails loudly and late.
