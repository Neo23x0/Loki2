
# Default make target
.DEFAULT_GOAL := build

# Loki binary name
BUILD_TARGET := 
LOKI_BINARY :=
ifeq ($(OS),Windows_NT)
	BUILD_TARGET=--target x86_64-pc-windows-gnu
	LOKI_BINARY=loki.exe
endif
ifeq ($(UNAME), Darwin)
	BUILD_TARGET=
	LOKI_BINARY=loki
endif
ifeq ($(UNAME), Linux)
	BUILD_TARGET=--target x86_64-unknown-linux-musl 
	LOKI_BINARY=loki
endif

build:
	@echo [+] Building LOKI release version ...
	cargo build --release $(BUILD_TARGET)
	@echo [+] Build successful!

dist: build
	@echo [+] Cleaning up temporary and target directories ...
	rm -rf ./dist
	rm -rf ./tmp
	mkdir -p ./dist/loki/signatures
	mkdir ./tmp
	cp target/release/$(LOKI_BINARY) dist/loki/
	@echo [+] Downloading signature-base from Github.com ...
	wget https://github.com/Neo23x0/signature-base/archive/master.tar.gz -O ./tmp/signature-base.tar.gz
	tar -xvzf ./tmp/signature-base.tar.gz -C ./tmp
	@echo [+] Copying signatures and IOCs to the ./dist folder ...
	cp -r ./tmp/signature-base-master/yara ./dist/loki/signatures/yara
	cp -r ./tmp/signature-base-master/iocs ./dist/loki/signatures/iocs
	cp LICENSE ./dist/loki/
	rm -rf ./tmp
	@echo [!] A distributable version of LOKI has been created in the ./dist folder

clean: 
	@echo [+] Cleaning up ...
	rm -rf ./target
	rm -rf ./dist
	rm -rf ./tmp

.PHONY: build, dist, clean