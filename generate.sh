#!/usr/bin/env sh
set -ex
mkdir -p _site
cp -p schema.json _site/schema.json

perl -V > _site/index.html
date >> _site/index.html

perl generate-cpansa-data.pl > _site/cpansa.json
