TARGET = echo-server

build: build_darwin_arm64 build_darwin_amd64 \
	build_linux_amd64 build_linux_arm build_linux_arm64 \
	build_windows_amd64 build_windows_arm64

build_darwin_%: GOOS = darwin
build_linux_%: GOOS = linux
build_windows_%: GOOS = windows
build_windows_%: EXT = .exe

build_%_amd64: GOARCH = amd64
build_%_arm: GOARCH = arm
build_%_arm64: GOARCH = arm64

BINPATH = bin/$(TARGET)_$(GOOS)_$(GOARCH)$(EXT)

build_%:
	export GOOS=$(GOOS) GOARCH=$(GOARCH)

	go build -o $(BINPATH) .

	chmod +x $(BINPATH)
