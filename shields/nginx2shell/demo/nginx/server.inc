# SPDX-License-Identifier: BSD-2-Clause
#
# The server block both instances share: HTTP/2 over TLS with the
# certificate the image made, a page, an 8 MiB file and the SIMULATED
# post-exploit endpoint.

http2 on;
server_name localhost;
ssl_certificate /etc/nginx/n2s/cert.pem;
ssl_certificate_key /etc/nginx/n2s/key.pem;
ssl_protocols TLSv1.2 TLSv1.3;

root /usr/share/nginx/n2s;

location = /__simulated_rce {
	perl SimulatedRce::handler;
}

location / {
}
