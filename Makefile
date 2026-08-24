SHELL := /bin/bash

SCENARIO ?=
SUITE ?=
CONSOLE_ROOT ?= $(CURDIR)/target/fault-tests
CONSOLE_ADDR ?= 127.0.0.1:0
CONSOLE_ALLOW_NON_LOOPBACK ?=
FAULT_SCRIPT := $(CURDIR)/scripts/fault-test.sh
PROTOCOL_SCRIPT := $(CURDIR)/scripts/protocol-test.sh
PROTOCOL_COMPAT_SCRIPT := $(CURDIR)/scripts/protocol-compatibility.sh

.PHONY: check fmt fmt-check clippy test fault-check fault-list fault-preflight fault-run fault-run-dm fault-suite-template fault-suite-validate fault-suite-plan fault-suite-run fault-console-json fault-console-serve fault-dashboard-install fault-dashboard-port-forward fault-cleanup protocol-check protocol-list protocol-compatibility-mint protocol-suite-template protocol-suite-validate protocol-suite-plan protocol-suite-run protocol-cleanup protocol-validate-artifacts

check: fmt-check clippy test

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --all-targets -- -D warnings

test:
	cargo test --all-targets

fault-check: check
	bash -n $(FAULT_SCRIPT)

fault-list:
	@bash $(FAULT_SCRIPT) list

fault-preflight:
	@test -n "$(SCENARIO)" || (echo "SCENARIO is required, for example: make fault-preflight SCENARIO=io-eio" >&2; exit 1)
	bash $(FAULT_SCRIPT) preflight "$(SCENARIO)"

fault-run:
	@test -n "$(SCENARIO)" || (echo "SCENARIO is required, for example: make fault-run SCENARIO=io-eio" >&2; exit 1)
	bash $(FAULT_SCRIPT) run "$(SCENARIO)"

fault-run-dm:
	bash $(FAULT_SCRIPT) run dm-flakey

fault-suite-template:
	@bash $(FAULT_SCRIPT) suite-template

fault-suite-validate:
	@test -n "$(SUITE)" || (echo "SUITE is required, for example: make fault-suite-validate SUITE=suite.yaml" >&2; exit 1)
	bash $(FAULT_SCRIPT) suite-validate "$(SUITE)"

fault-suite-plan:
	@test -n "$(SUITE)" || (echo "SUITE is required, for example: make fault-suite-plan SUITE=suite.yaml" >&2; exit 1)
	bash $(FAULT_SCRIPT) suite-plan "$(SUITE)"

fault-suite-run:
	@test -n "$(SUITE)" || (echo "SUITE is required, for example: make fault-suite-run SUITE=suite.yaml" >&2; exit 1)
	bash $(FAULT_SCRIPT) suite-run "$(SUITE)"

fault-console-json:
	cargo run --quiet --manifest-path Cargo.toml --bin s3chaos -- fault-console-json "$(CONSOLE_ROOT)"

fault-console-serve:
	cargo run --quiet --manifest-path Cargo.toml --bin s3chaos -- fault-console-serve "$(CONSOLE_ROOT)" --addr "$(CONSOLE_ADDR)" $(CONSOLE_ALLOW_NON_LOOPBACK)

fault-dashboard-install:
	bash $(FAULT_SCRIPT) dashboard-install

fault-dashboard-port-forward:
	bash $(FAULT_SCRIPT) dashboard-port-forward

fault-cleanup:
	bash $(FAULT_SCRIPT) cleanup

protocol-check: check
	bash -n $(PROTOCOL_SCRIPT)
	bash -n $(PROTOCOL_COMPAT_SCRIPT)

protocol-list:
	@bash $(PROTOCOL_SCRIPT) list

protocol-compatibility-mint:
	bash $(PROTOCOL_COMPAT_SCRIPT) mint

protocol-suite-template:
	@bash $(PROTOCOL_SCRIPT) suite-template

protocol-suite-validate:
	@test -n "$(SUITE)" || (echo "SUITE is required, for example: make protocol-suite-validate SUITE=suite.yaml" >&2; exit 1)
	bash $(PROTOCOL_SCRIPT) suite-validate "$(SUITE)"

protocol-suite-plan:
	@test -n "$(SUITE)" || (echo "SUITE is required, for example: make protocol-suite-plan SUITE=suite.yaml" >&2; exit 1)
	bash $(PROTOCOL_SCRIPT) suite-plan "$(SUITE)"

protocol-suite-run:
	@test -n "$(SUITE)" || (echo "SUITE is required, for example: make protocol-suite-run SUITE=suite.yaml" >&2; exit 1)
	bash $(PROTOCOL_SCRIPT) suite-run "$(SUITE)"

protocol-cleanup:
	@test -n "$(ARTIFACT_ROOT)" || (echo "ARTIFACT_ROOT is required, for example: make protocol-cleanup ARTIFACT_ROOT=target/protocol-tests/..." >&2; exit 1)
	bash $(PROTOCOL_SCRIPT) cleanup "$(ARTIFACT_ROOT)"

protocol-validate-artifacts:
	@test -n "$(ARTIFACT_ROOT)" || (echo "ARTIFACT_ROOT is required, for example: make protocol-validate-artifacts ARTIFACT_ROOT=target/protocol-tests/..." >&2; exit 1)
	bash $(PROTOCOL_SCRIPT) validate-artifacts "$(ARTIFACT_ROOT)"
