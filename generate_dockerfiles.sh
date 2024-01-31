#!/bin/sh

cat <<EOF | mustache - Dockerfile.template > chrome/Dockerfile
---
chrome: true
debian: true
---
EOF
cat <<EOF | mustache - Dockerfile.template > chrome/Dockerfile.alpine
---
chrome: true
alpine: true
---
EOF
