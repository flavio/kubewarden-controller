SOURCES=$(shell find . -name "*.rego")
OBJECTS=$(SOURCES:%.rego=%.wasm)

# entrypoint of the Rego policy, differs from policy to policy
gatekeeper.wasm: ENTRYPOINT=policy/violation
trace.wasm: ENTRYPOINT=policy/main

.PHONY: all
all: $(OBJECTS)

%.wasm: %.rego
	opa build --v0-compatible -t wasm -e $(ENTRYPOINT) -o $*.tar.gz $<
	tar -xf $*.tar.gz --transform "s|policy.wasm|$*.wasm|" /policy.wasm
	rm $*.tar.gz

.PHONY: clean
clean:
	rm -f *.wasm *.tar.gz
