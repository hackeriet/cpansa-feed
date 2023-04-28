#!/usr/bin/env sh
set -ex
mkdir -p _site
cp -p schema.json _site/schema.json
cp -p cpansa_dev.json _site/cpansa_dev.json

perl -V > _site/index.html
date >> _site/index.html

#perl generate-cpansa-data.pl > _site/cpansa.json
cp -p cpansa-patched.json _site/cpansa.json
