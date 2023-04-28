#!/usr/bin/env sh
set -ex
mkdir -p _site
perl -V > _site/index.html
date >> _site/index.html
