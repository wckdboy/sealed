CARGO ?= cargo
NPM ?= npm
PORT ?= 8099

.PHONY: help check rust web live vectors dev fmt clean docker publish-public clean-clone

help:
	@echo "make check    - full gate (fmt, clippy, rust tests, web tests, web build, vectors)"
	@echo "make rust     - cargo fmt --check, clippy -D warnings, cargo test"
	@echo "make web      - typecheck, vitest (conformance), vite build"
	@echo "make live     - boot the API and run web/src/live.test.ts against it"
	@echo "make vectors  - regenerate + verify spec/crypto-vectors.json"
	@echo "make dev      - run the API in dev mode on 127.0.0.1:8080"
	@echo "make docker   - build the single-container image (API + web) as \`vault\`"
	@echo "make publish-public PUBLIC_REMOTE=<url> - publish the neutral-brand mirror"

check: fmt rust web vectors

fmt:
	$(CARGO) fmt --all -- --check

rust:
	$(CARGO) clippy --all-targets -- -D warnings
	VAULT_REQUIRE_JS_INTEROP=1 $(CARGO) test --all

web:
	cd web && $(NPM) ci --no-audit --no-fund && npx tsc --noEmit && npx vitest run && $(NPM) run build

vectors:
	$(CARGO) run -q -p vault-core --bin vecgen -- --check

live:
	@rm -rf /tmp/vault-live && mkdir -p /tmp/vault-live/blobs
	@VAULT_DEV=1 VAULT_BIND=127.0.0.1:$(PORT) \
	  DATABASE_URL=sqlite:/tmp/vault-live/live.db \
	  VAULT_BLOB_DIR=/tmp/vault-live/blobs \
	  VAULT_DEFAULT_TIER=premium1 \
	  $(CARGO) run -q -p vault-api > /tmp/vault-live/server.log 2>&1 & \
	 echo $$! > /tmp/vault-live/pid
	@for i in $$(seq 1 60); do \
	  if curl -fsS http://127.0.0.1:$(PORT)/healthz > /dev/null 2>&1; then break; fi; \
	  sleep 1; \
	done; \
	curl -fsS http://127.0.0.1:$(PORT)/healthz || { echo "server did not start:"; tail -20 /tmp/vault-live/server.log; exit 1; }
	@cd web && VAULT_LIVE_BASE=http://127.0.0.1:$(PORT) npx vitest run src/live.test.ts; \
	 rc=$$?; kill $$(cat /tmp/vault-live/pid) 2>/dev/null; exit $$rc

# Proves the committed tree is complete: a fresh clone must build and pass its own
# tests. Catches files that exist locally but were never added (e.g. a wordlist
# swallowed by an over-broad .gitignore entry).
clean-clone:
	@tmp=$$(mktemp -d); \
	 git clone -q --depth 1 "$$(git config --get remote.origin.url)" "$$tmp/repo" && \
	 ( cd "$$tmp/repo/web" && npm ci --no-audit --no-fund >/dev/null && npx tsc --noEmit && npx vitest run ) && \
	 ( cd "$$tmp/repo" && \
	   cargo fmt --all -- --check && \
	   VAULT_REQUIRE_JS_INTEROP=1 cargo test --all && \
	   cargo run -q -p vault-core --bin vecgen -- --check ); \
	 rc=$$?; rm -rf "$$tmp"; exit $$rc

docker:
	docker build -t vault .

# The mirror is generated, never edited (docs/adr/0010). Point PUBLIC_REMOTE at the
# public repo; this force-pushes to it.
publish-public:
	@test -n "$(PUBLIC_REMOTE)" || { echo "set PUBLIC_REMOTE=git@github.com:OWNER/NAME.git"; exit 2; }
	scripts/publish-public.sh $(PUBLIC_REMOTE) --verify

dev:
	VAULT_DEV=1 VAULT_BIND=127.0.0.1:8080 \
	  DATABASE_URL=sqlite:data/vault.db VAULT_BLOB_DIR=data/blobs \
	  $(CARGO) run -p vault-api

clean:
	$(CARGO) clean
	rm -rf web/dist web/.conformance /tmp/vault-live
