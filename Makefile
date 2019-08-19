# https://www.gnu.org/prep/standards/html_node/Directory-Variables.html#Directory-Variables
PREFIX    ?= /usr/local
BINPREFIX ?= $(PREFIX)/bin
DISTDIR   := dist
TARGET    := mrs
PLATFORMS := darwin freebsd linux

.PHONY: $(PLATFORMS) $(TARGET) all clean install release test uninstall

all: $(TARGET)

$(PLATFORMS):
	GOARCH=amd64 GOOS=$@ go build -o "$(DISTDIR)/$(TARGET)-$@-amd64"

$(TARGET):
	go build -o $@

clean:
	go clean
	rm -f "$(DISTDIR)/$(TARGET)*"

install: $(TARGET)
	sudo mkdir -p "$(DESTDIR)$(BINPREFIX)"
	sudo cp -pf $(TARGET) "$(DESTDIR)$(BINPREFIX)/"

release: clean $(PLATFORMS)

test:
	go test -v ./...

uninstall:
	rm -f "$(DESTDIR)$(BINPREFIX)/$(TARGET)"
