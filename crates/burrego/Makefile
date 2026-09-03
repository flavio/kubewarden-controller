TESTDIRS := $(wildcard tests/e2e/*)
.PHONY: $(TESTDIRS)

.PHONY: fmt
fmt:
	cargo +nightly fmt --all -- --check

.PHONY: lint
lint:
	cargo clippy -- -D warnings

.PHONY: test
test: fmt lint e2e-tests
	cargo test

.PHONY: unit-tests
unit-tests:
	cargo test --lib

.PHONY: clean
clean:
	cargo clean

# Rebuild the Wasm modules committed under tests/data/. Requires
# `opa` to be installed; only needed when adding/changing a fixture, not
# for running the test suite.
.PHONY: policies
policies:
	$(MAKE) -C tests/data

.PHONY: e2e-tests
e2e-tests: $(TESTDIRS)
$(TESTDIRS):
	$(MAKE) -C $@
