#!/bin/sh

cat <<EOF | mustache - Dockerfile.template > chrome/Dockerfile
---
chrome: true
---
EOF

cat <<EOF | mustache - Dockerfile.template > firefox/Dockerfile
---
firefox: true
---
EOF
