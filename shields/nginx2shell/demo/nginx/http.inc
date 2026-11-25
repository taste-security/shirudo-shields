# SPDX-License-Identifier: BSD-2-Clause
#
# The http block both instances share.

include /etc/nginx/mime.types;
default_type application/octet-stream;
sendfile on;
keepalive_timeout 65;

perl_modules /etc/nginx/n2s/perl;
perl_require SimulatedRce.pm;
