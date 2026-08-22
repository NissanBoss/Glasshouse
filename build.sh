#!/bin/sh
# Build the packages that get published.
#
#   sh build.sh          a local build, version reads "unreleased"
#   sh build.sh v1        stamped with a version
#
# The release workflow calls this same script rather than repeating what it
# does. Two copies of a build recipe drift apart, and by the time anyone
# notices, some release has been going out wrong for months.

set -e
cd "$(dirname "$0")"
rm -rf dist
mkdir -p dist

# -s -w drops the debug information; the binary is a lot smaller for it.
FLAGS="-s -w"

# The version comes from the tag being published. Pass it as an argument by
# hand, or let the workflow supply GITHUB_REF_NAME. With neither, the binary
# says "unreleased", which is exactly what you want to see so you never
# mistake a local build for a downloaded one.
VERSION="${1:-$GITHUB_REF_NAME}"
if [ -n "$VERSION" ]; then
    FLAGS="$FLAGS -X main.version=$VERSION"
    echo "Version: $VERSION"
else
    echo "Version: unreleased (no tag given)"
fi
echo ""

echo "Checking before building..."
if [ -n "$(gofmt -l .)" ]; then
    echo "  these files are not formatted:"
    gofmt -l .
    exit 1
fi
go vet ./...
go test ./... >/dev/null
echo "  all good"
echo ""

# pack <folder> <os> <arch> <binary name>
pack() {
    FOLDER="dist/$1"
    mkdir -p "$FOLDER"
    # -trimpath keeps the path this was built from out of the binary. Without
    # it, anyone who opens the file sees the directory it came from, which in
    # a privacy tool would be a poor way to start.
    GOOS="$2" GOARCH="$3" go build -trimpath -ldflags "$FLAGS" -o "$FOLDER/$4" .
    cp README.md LICENSE "$FOLDER/"
    echo "  $1"
}

echo "Building..."
pack glasshouse-windows      windows amd64 glasshouse.exe
pack glasshouse-linux        linux   amd64 glasshouse
pack glasshouse-linux-arm    linux   arm64 glasshouse
pack glasshouse-mac-apple    darwin  arm64 glasshouse
pack glasshouse-mac-intel    darwin  amd64 glasshouse

echo ""
echo "Compressing..."
cd dist
for P in glasshouse-windows glasshouse-linux glasshouse-linux-arm \
         glasshouse-mac-apple glasshouse-mac-intel; do
    if [ "$P" = "glasshouse-windows" ]; then
        # zip first: it is what Linux and the workflow have. powershell is
        # the fallback for building on Windows, where zip is not standard.
        # Never tar: GNU tar cannot write a zip and would leave a broken file
        # without saying a word.
        if command -v zip >/dev/null 2>&1; then
            zip -qr "$P.zip" "$P"
        elif command -v powershell >/dev/null 2>&1; then
            powershell -NoProfile -Command \
                "Compress-Archive -Path '$P' -DestinationPath '$P.zip' -Force" >/dev/null
        else
            echo "  found neither zip nor powershell to compress $P"
            exit 1
        fi
    else
        tar -czf "$P.tar.gz" "$P"
    fi
done
cd ..

echo ""
for F in dist/*.zip dist/*.tar.gz; do
    [ -f "$F" ] && printf "  %-32s %s\n" "$(basename "$F")" "$(du -h "$F" | cut -f1)"
done
echo ""
echo "Done."
