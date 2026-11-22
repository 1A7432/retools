#!/bin/sh
# Build the jsvm1-tools image and record its id in IMAGE_DIGEST.
# Network is needed only to fill cache/ the first time (nodejs.org, PyPI, npm)
# and for apt inside the build; every download is checked against a pinned hash.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"
NODE_VER=v22.21.1
case "$(docker info --format '{{.Architecture}}')" in
  aarch64|arm64) ARCH=arm64; PYPLAT=manylinux2014_aarch64; NODE_SHA=e660365729b434af422bcd2e8e14228637ecf24a1de2cd7c916ad48f2a0521e1 ;;
  x86_64|amd64)  ARCH=x64;   PYPLAT=manylinux2014_x86_64;  NODE_SHA=680d3f30b24a7ff24b98db5e96f294c0070f8f9078df658da1bce1b9c9873c88 ;;
  *) echo "unsupported docker architecture" >&2; exit 1 ;;
esac
NODE_DIST=node-$NODE_VER-linux-$ARCH
mkdir -p cache/wheels
if [ ! -f "cache/$NODE_DIST.tar.xz" ]; then
  curl -fsSL -o "cache/$NODE_DIST.tar.xz.part" "https://nodejs.org/dist/$NODE_VER/$NODE_DIST.tar.xz"
  mv "cache/$NODE_DIST.tar.xz.part" "cache/$NODE_DIST.tar.xz"
fi
echo "$NODE_SHA  cache/$NODE_DIST.tar.xz" | shasum -a 256 -c -
if [ -z "$(ls cache/wheels)" ]; then
  python3 -m pip download --quiet --no-deps --only-binary=:all: --platform "$PYPLAT" \
      --python-version 3.13 --implementation cp --dest cache/wheels -r requirements.txt
fi
if [ ! -d cache/node_modules ]; then
  rm -rf cache/npm && mkdir -p cache/npm
  cp package.json package-lock.json cache/npm/
  (cd cache/npm && npm ci --ignore-scripts --no-audit --no-fund --omit=dev)
  mv cache/npm/node_modules cache/node_modules && rm -rf cache/npm
fi
docker build --build-arg NODE_DIST="$NODE_DIST" -t jsvm1-tools:1 .
docker image inspect --format '{{.Id}}' jsvm1-tools:1 > IMAGE_DIGEST
echo "jsvm1-tools:1 $(cat IMAGE_DIGEST)"
