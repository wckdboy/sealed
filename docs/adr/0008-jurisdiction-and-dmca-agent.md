# ADR 0008 — Jurisdiction and the DMCA agent: an unresolved conflict

**Status:** **OPEN — needs a founder decision before launch**
**Date:** 2026-10-25

## Context

Section 8 of the master plan contains two requirements that pull in opposite
directions:

1. "DMCA safe-harbor posture: registered DMCA agent (~$6 at copyright.gov —
   entity registered, not you personally)."
2. "Njalla + XMR only, separate device for admin" — i.e. the operator's identity is
   compartmentalised and the corporate footprint is deliberately thin.

They conflict because:

- US 17 U.S.C. §512(c) safe harbour *requires* designating an agent with the US
  Copyright Office, which requires a legal entity name and address of record. That
  is a durable, public, subpoena-addressable link to the operator.
- US 18 U.S.C. §2258A obliges electronic service providers to report apparent
  CSAM to NCMEC. An "ESP" with US users almost always is one, and the reporting
  duty presumes knowledge of the content — precisely what a zero-knowledge design
  refuses to have. §2258A(f) contemplates hash-matching for encrypted services;
  it is a narrow, contested lane, not a blanket protection.
- Choosing *not* to register a US agent (staying non-US, no US entity, blocking US
  traffic is impractical for a public site) means operating without safe harbour
  and with a standing legal exposure that no amount of encryption reduces.
- Child-safety law is the one area where "we cannot see it" is not a defence
  anywhere. If the platform is used for CSAM, the operator's exposure (and mine,
  as the person who built the pipeline) is criminal in most jurisdictions,
  regardless of the encryption story.

## The decision that is actually required

Pick one posture, deliberately, and write it into the ToS:

**A. Regulated adult platform (recommended if the business is real).**
Register an entity in a jurisdiction where adult UGC is lawful and where a
2257/2258A-equivalent duty is clear (EU/DACH or NL, with a US DMCA agent as well).
Operate semi-anonymously (Njalla for DNS only), accept that payouts and the
entity are known to a bank/PSP, and treat "anonymous to users, accountable to
regulators" as the product stance. This is the only posture where the plan's
CSAM section is credible.

**B. Tor-only / invitation-only / no public feed.**
No public streaming, no search, no discovery: private vaults and passphrase
shares only. Much smaller surface, much smaller legal exposure, much slower
growth. PKEK and the public feed come out entirely.

**C. Public anonymous feed with crypto payments and no registered agent.**
This is what the plan literally describes. It is also the configuration that, in
the event of a CSAM or non-consensual-content incident, leaves the operator with
no safe harbour, no takedown process that survives contact with a subpoena, and a
platform whose entire architecture argues *against* the duty to report. **Not
recommended.** If chosen, it needs a lawyer's written opinion first, not a
developer's.

## Consequences for the code

The code is posture-neutral by design, so this decision does not block phase 0:

- `/dmca` exists and takes a configurable contact (`VAULT_DMCA_CONTACT`).
- `mod_log` records every quarantine/takedown with timestamps and evidence refs —
  the artefact any posture needs.
- Upload gating (paid tier + quota + strikes) is implemented now because it is the
  cheapest risk reduction available under all three postures.
- Nothing in the stack requires the operator's identity to function, so moving
  from C to A later is a legal and banking exercise, not a rewrite.

**Until this ADR is resolved to A or B, do not open a public feed to real users.**
