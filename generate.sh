#!/usr/bin/env sh
set -ex
mkdir -p _site
cp -p schema.json _site/schema.json
cp -p cpansa_dev.json _site/cpansa_dev.json

now=$(date)
echo "<h1>cpansa-feed updated $now</h1><a href=cpansa.json>cpansa.json</a>" > _site/index.html

perl generate-cpansa-data.pl > _site/cpansa.json
#cp -p cpansa-patched.json _site/cpansa-patched.json
