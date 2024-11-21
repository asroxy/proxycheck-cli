#!/bin/bash

install_proxycheck() {
    OS=$(uname -s)
    URL=""
    DEST="/usr/local/bin"

    case "$OS" in
        Linux)
            URL="https://github.com/asroxy/proxycheck-cli/releases/download/v1.01/proxycheck_linux.zip"
            ;;
        Darwin)
            URL="https://github.com/asroxy/proxycheck-cli/releases/download/v1.01/proxycheck_macos.zip"
            ;;
        FreeBSD|OpenBSD)
            URL="https://github.com/asroxy/proxycheck-cli/releases/download/v1.01/proxycheck_bsd.zip"
            ;;
        SunOS)
            URL="https://github.com/asroxy/proxycheck-cli/releases/download/v1.01/proxycheck_sunos.zip"
            ;;
        *)
            echo "Unsupported OS: $OS"
            exit 1
            ;;
    esac

    echo "Downloading Proxycheck for $OS..."
    curl -L -o /tmp/proxycheck.zip "$URL"

    echo "Extracting..."
    unzip /tmp/proxycheck.zip -d /tmp/proxycheck

    if [ "$OS" == "Darwin" ]; then
        echo "Running xattr to remove quarantine attribute on MacOS..."
        xattr -dr com.apple.quarantine /tmp/proxycheck/proxycheck
    fi

    echo "Installing to $DEST..."

    if [ "$(id -u)" -ne 0 ]; then
        echo "You need to run this script as root (sudo)."
        exit 1
    fi

    mv /tmp/proxycheck/proxycheck "$DEST"

    echo "Cleaning up..."
    rm -rf /tmp/proxycheck
    rm /tmp/proxycheck.zip

    echo "Installation complete."
}

if [ "$(id -u)" -ne 0 ]; then
    echo "You need to run this script as root or with sudo."
    exit 1
fi

install_proxycheck
