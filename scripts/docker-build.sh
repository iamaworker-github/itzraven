#!/bin/bash
# Build and optionally push Itzraven Docker image
set -e

VERSION="${1:-latest}"
REGISTRY="${2:-docker.io}"
REPO="${3:-itzraven-security/itzraven}"

echo "Building Itzraven v${VERSION}..."
echo "   Registry: ${REGISTRY}"
echo "   Repo:     ${REPO}"
echo ""

# Build runtime image
docker build \
    --target runtime \
    -t "${REPO}:${VERSION}" \
    -t "${REPO}:latest" \
    --build-arg BUILDKIT_INLINE_CACHE=1 \
    .

echo ""
echo "Built: ${REPO}:${VERSION}"
echo ""

# Build full image (includes nuclei, httpx, nmap)
echo "Building full image (with heavy tools)..."
docker build \
    --target full \
    -t "${REPO}:${VERSION}-full" \
    -t "${REPO}:full" \
    .
echo "Built: ${REPO}:${VERSION}-full"
echo ""

# Push if requested
if [ -n "${DOCKER_PUSH}" ]; then
    echo "Pushing to ${REGISTRY}..."
    docker push "${REPO}:${VERSION}"
    docker push "${REPO}:latest"
    docker push "${REPO}:${VERSION}-full"
    docker push "${REPO}:full"
    echo "Pushed!"
fi

echo ""
echo "Usage:"
echo "  docker run --rm -it ${REPO}:${VERSION} --target https://example.com"
echo "  docker run --rm -it ${REPO}:${VERSION} deep --target https://example.com"
echo "  docker run --rm -it ${REPO}:${VERSION} whitebox --target /app/target"
echo "  docker run --rm -it -e STRICT_POC=strict ${REPO}:${VERSION} deep --target https://example.com"
echo ""
