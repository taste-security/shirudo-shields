# SPDX-License-Identifier: BSD-2-Clause
#
# The web server the nginx2shell shield is shown around: two nginx
# instances from the Docker "official images", both with HTTP/2, TLS and
# the embedded Perl module, both linked to the same dynamic OpenSSL.
#
#   nginx 1.31.8 at /usr/sbin/nginx        port 8443  vulnerable range
#   nginx 1.31.9 at /usr/local/sbin/nginx  port 9443  fixed release
#
# Both images are Alpine 3.24.4 with OpenSSL 3.5.9 and Perl 5.42.3, so
# the 1.31.9 binary runs on the 1.31.8 image's libraries; the RUN below
# refuses to build if that ever stops being true. libssl is
# /usr/lib/libssl.so.3, the path the h2guard upatch probes by default.
#
# The digests pin the multi-arch indexes (amd64 for CI, arm64 for a Mac).

FROM nginx:1.31.9-alpine-perl@sha256:8b965e7cdebebd0082ee56821d3f853a34cccb18762b0ed2dfd5f6fb9005f74c AS patched

# A certificate for the demo alone, made when the image is built, in a
# stage of its own so that the final image gets no extra package.
FROM nginx:1.31.8-alpine-perl@sha256:e52e29caed0b6b368204f867ad2edf5b967ec90323b6a6a7a90fc9031930b2c6 AS cert
RUN apk add --no-cache openssl >/dev/null \
	&& openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
		-nodes -keyout /key.pem -out /cert.pem -subj /CN=localhost \
		-days 3650 2>/dev/null

FROM nginx:1.31.8-alpine-perl@sha256:e52e29caed0b6b368204f867ad2edf5b967ec90323b6a6a7a90fc9031930b2c6

COPY --from=patched /usr/sbin/nginx /usr/local/sbin/nginx
COPY --from=patched /usr/lib/nginx/modules/ngx_http_perl_module.so /usr/lib/nginx/modules-1.31.9/ngx_http_perl_module.so
COPY --from=patched /usr/lib/perl5/vendor_perl/ /opt/patched-perl/
COPY --from=patched /usr/lib/libssl.so.3 /usr/lib/libcrypto.so.3 /opt/patched-libs/
COPY --from=patched /usr/lib/perl5/core_perl/CORE/libperl.so /opt/patched-libs/
COPY --from=cert /cert.pem /key.pem /etc/nginx/n2s/
COPY nginx/ /etc/nginx/n2s/
COPY perl/ /etc/nginx/n2s/perl/
COPY html/ /usr/share/nginx/n2s/
COPY n2s-run /usr/local/bin/n2s-run

# nginx.pm and its XS object are tied to the nginx version that built
# them, and sit in an architecture directory that is not on libperl's
# @INC, so each version gets its own copy, which its configuration names
# with perl_modules.
# /var/lib/n2s-drop is owned by the worker, so the SIMULATED file drops of
# SimulatedRce.pm succeed without the shield and only its deny rules refuse them.
RUN set -e; \
	cmp /opt/patched-libs/libssl.so.3 /usr/lib/libssl.so.3; \
	cmp /opt/patched-libs/libcrypto.so.3 /usr/lib/libcrypto.so.3; \
	cmp /opt/patched-libs/libperl.so /usr/lib/perl5/core_perl/CORE/libperl.so; \
	for v in 1.31.8:/usr/lib/perl5/vendor_perl 1.31.9:/opt/patched-perl; do \
		src=$(dirname "$(find "${v#*:}" -name nginx.pm)"); \
		mkdir -p "/usr/local/lib/nginx-${v%%:*}/perl"; \
		cp -a "$src/nginx.pm" "$src/auto" "/usr/local/lib/nginx-${v%%:*}/perl/"; \
	done; \
	rm -rf /opt/patched-perl /opt/patched-libs; \
	chmod 0755 /usr/local/bin/n2s-run; \
	chmod 0600 /etc/nginx/n2s/key.pem; \
	for i in vulnerable patched; do \
		mkdir -p "/var/cache/nginx/n2s-$i"; \
	done; \
	install -d -o nginx -g nginx -m 0755 /var/lib/n2s-drop; \
	dd if=/dev/urandom of=/usr/share/nginx/n2s/big.bin bs=1M count=8 2>/dev/null; \
	/usr/sbin/nginx -v 2>&1 | grep -qx 'nginx version: nginx/1.31.8'; \
	/usr/local/sbin/nginx -v 2>&1 | grep -qx 'nginx version: nginx/1.31.9'; \
	/usr/sbin/nginx -t -q -c /etc/nginx/n2s/vulnerable.conf; \
	/usr/local/sbin/nginx -t -q -c /etc/nginx/n2s/patched.conf

EXPOSE 8443 9443
STOPSIGNAL SIGQUIT
ENTRYPOINT []
CMD ["/usr/local/bin/n2s-run", "foreground"]
