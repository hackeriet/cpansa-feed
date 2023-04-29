#!/usr/bin/env sh
set -ex


## Normally, this is fine
##
# cpm install -g

## But we want the latest cpan-audit and update cpan-s-a repo so we're not
## depending on it being released on CPAN
##
cpanm -n --installdeps CPAN::Audit

# for util/generate
cpanm -n YAML::Tiny Mojolicious

# for generate-cpansa-data.pl
cpanm -n JSON::MaybeXS JSON::Schema::Modern Path::Tiny


mkdir -p /app
cd /app
git clone https://github.com/briandfoy/cpan-audit
cd cpan-audit
# Get latest submodules, i.e. cpan-security-advisory
git submodule init
git submodule update --recursive --remote

util/generate

perl Makefile.PL
make && make install
