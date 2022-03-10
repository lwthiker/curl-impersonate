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

cat <<EOF | mustache - Dockerfile.template > firefox/Dockerfile
---
firefox: true
debian: true
---
EOF

cat <<EOF | mustache - Dockerfile.template > firefox/Dockerfile.alpine
---
firefox: true
alpine: true
---
EOF
