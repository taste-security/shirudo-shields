# SPDX-License-Identifier: BSD-2-Clause
"""Just enough HTTP/2 (RFC 9113) over TLS for h2probe and h2client.

Python standard library only, so that the tools run on a Shirudo target's
own python3 with nothing installed. It frames, reads and writes; HPACK is
reduced to what the tools need: literal request headers out, and the
:status of a response in (nginx sends it as the first field).
"""

import socket
import ssl
import struct
import time

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

DATA = 0x0
HEADERS = 0x1
PRIORITY = 0x2
RST_STREAM = 0x3
SETTINGS = 0x4
PUSH_PROMISE = 0x5
PING = 0x6
GOAWAY = 0x7
WINDOW_UPDATE = 0x8
CONTINUATION = 0x9

FRAME_NAMES = {
    DATA: "DATA", HEADERS: "HEADERS", PRIORITY: "PRIORITY",
    RST_STREAM: "RST_STREAM", SETTINGS: "SETTINGS",
    PUSH_PROMISE: "PUSH_PROMISE", PING: "PING", GOAWAY: "GOAWAY",
    WINDOW_UPDATE: "WINDOW_UPDATE", CONTINUATION: "CONTINUATION",
}

FLAG_END_STREAM = 0x1
FLAG_ACK = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20

SETTINGS_INITIAL_WINDOW_SIZE = 0x4
SETTINGS_MAX_FRAME_SIZE = 0x5

ERROR_NAMES = {
    0x0: "NO_ERROR", 0x1: "PROTOCOL_ERROR", 0x2: "INTERNAL_ERROR",
    0x3: "FLOW_CONTROL_ERROR", 0x4: "SETTINGS_TIMEOUT",
    0x5: "STREAM_CLOSED", 0x6: "FRAME_SIZE_ERROR",
    0x7: "REFUSED_STREAM", 0x8: "CANCEL", 0x9: "COMPRESSION_ERROR",
    0xa: "CONNECT_ERROR", 0xb: "ENHANCE_YOUR_CALM",
    0xc: "INADEQUATE_SECURITY", 0xd: "HTTP_1_1_REQUIRED",
}
CANCEL = 0x8

MAX_WINDOW = 2**31 - 1


class Closed(Exception):
    """The peer closed or reset the connection."""


def frame(ftype, flags, stream, payload=b""):
    return (struct.pack(">I", len(payload))[1:]
            + struct.pack(">BBI", ftype, flags, stream & MAX_WINDOW)
            + payload)


def settings(pairs=(), ack=False):
    payload = b"".join(struct.pack(">HI", k, v) for k, v in pairs)
    return frame(SETTINGS, FLAG_ACK if ack else 0, 0, payload)


def window_update(stream, increment):
    return frame(WINDOW_UPDATE, 0, stream, struct.pack(">I", increment))


def rst_stream(stream, code=CANCEL):
    return frame(RST_STREAM, 0, stream, struct.pack(">I", code))


def ping_ack(opaque):
    return frame(PING, FLAG_ACK, 0, opaque)


def _hpack_int(value, prefix_bits, first=0):
    limit = (1 << prefix_bits) - 1
    if value < limit:
        return bytes([first | value])
    out = [first | limit]
    value -= limit
    while value >= 128:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _hpack_str(s):
    b = s.encode("ascii")
    return _hpack_int(len(b), 7) + b


def request_headers(authority, path, method="GET"):
    """A header block of literal fields without indexing, no Huffman."""
    block = b""
    for name, value in ((":method", method), (":scheme", "https"),
                        (":authority", authority), (":path", path),
                        ("user-agent", "shirudo-shields-h2/1")):
        block += b"\x00" + _hpack_str(name) + _hpack_str(value)
    return block


def headers(stream, block, end_stream=True):
    flags = FLAG_END_HEADERS | (FLAG_END_STREAM if end_stream else 0)
    return frame(HEADERS, flags, stream, block)


# HPACK static table entries 8 to 14 are :status values.
_STATIC_STATUS = {8: 200, 9: 204, 10: 206, 11: 304, 12: 400, 13: 404, 14: 500}
# Huffman codes of the digits (RFC 7541 Appendix B), for a status
# literal the encoder chose to compress.
_HUFF_DIGITS = {
    ("00000"): "0", ("00001"): "1", ("00010"): "2", ("011001"): "3",
    ("011010"): "4", ("011011"): "5", ("011100"): "6", ("011101"): "7",
    ("011110"): "8", ("011111"): "9",
}


def _huffman_digits(data):
    bits = "".join(format(b, "08b") for b in data)
    out, code = "", ""
    for bit in bits:
        code += bit
        if code in _HUFF_DIGITS:
            out += _HUFF_DIGITS[code]
            code = ""
            if len(out) == 3:
                break
    return out


def response_status(block):
    """The :status of a response header block, or None if not first."""
    if not block:
        return None
    b = block[0]
    if b & 0x80:
        return _STATIC_STATUS.get(b & 0x7f)
    if b & 0x40:
        index, rest = b & 0x3f, block[1:]
    elif b & 0xe0 == 0:
        index, rest = b & 0x0f, block[1:]
    else:
        return None
    if index != 8 or not rest:
        return None
    huff, length = rest[0] & 0x80, rest[0] & 0x7f
    value = rest[1:1 + length]
    text = _huffman_digits(value) if huff else value.decode("ascii", "replace")
    try:
        return int(text)
    except ValueError:
        return None


def describe(ftype, flags, stream, payload):
    name = FRAME_NAMES.get(ftype, "type%#x" % ftype)
    extra = ""
    if ftype == GOAWAY and len(payload) >= 8:
        last, code = struct.unpack(">II", payload[:8])
        extra = " last_stream=%d error=%s" % (
            last & MAX_WINDOW, ERROR_NAMES.get(code, "%#x" % code))
    elif ftype == RST_STREAM and len(payload) >= 4:
        code = struct.unpack(">I", payload[:4])[0]
        extra = " error=%s" % ERROR_NAMES.get(code, "%#x" % code)
    elif ftype == WINDOW_UPDATE and len(payload) >= 4:
        extra = " increment=%d" % (struct.unpack(">I", payload[:4])[0] & MAX_WINDOW)
    elif ftype == DATA:
        extra = " length=%d" % len(payload)
    return "%s stream=%d flags=%#x%s" % (name, stream, flags, extra)


def goaway_error(payload):
    code = struct.unpack(">II", payload[:8])[1]
    return ERROR_NAMES.get(code, "%#x" % code)


def parse_target(url):
    """https://host:port[/path] -> (host, port)."""
    if not url.startswith("https://"):
        raise ValueError("only https:// targets: %s" % url)
    rest = url[len("https://"):].split("/", 1)[0]
    if rest.startswith("["):
        host, _, port = rest[1:].partition("]")
        port = port.lstrip(":")
    else:
        host, _, port = rest.partition(":")
    return host, int(port or 443)


def tls_context(alpn, cafile=None):
    ctx = ssl.create_default_context(cafile=cafile)
    if cafile is None:
        # The demo's certificate is self-signed.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(alpn)
    return ctx


def server_header(host, port, timeout=5.0, cafile=None):
    """The Server header of an HTTP/1.1 HEAD / over TLS, or None."""
    ctx = tls_context(["http/1.1"], cafile)
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            s.sendall(("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n"
                       "User-Agent: shirudo-shields-h2/1\r\n\r\n" % host).encode())
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
    for line in data.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"server":
            return value.strip().decode("ascii", "replace")
    return None


class Connection:
    """One HTTP/2 connection over TLS."""

    def __init__(self, host, port, timeout=5.0, cafile=None):
        self.host, self.port = host, port
        ctx = tls_context(["h2"], cafile)
        raw = socket.create_connection((host, port), timeout=timeout)
        self.sock = ctx.wrap_socket(raw, server_hostname=host)
        if self.sock.selected_alpn_protocol() != "h2":
            self.sock.close()
            raise RuntimeError("the server did not negotiate h2 over ALPN")
        self.buf = b""
        self.authority = "%s:%d" % (host, port)

    def send(self, data):
        try:
            self.sock.sendall(data)
        except (ConnectionError, ssl.SSLError, OSError) as e:
            raise Closed("send: %s" % e.__class__.__name__) from e

    def _recv_exact(self, n, deadline):
        while len(self.buf) < n:
            left = deadline - time.monotonic()
            if left <= 0:
                raise socket.timeout()
            self.sock.settimeout(left)
            try:
                chunk = self.sock.recv(65536)
            except ssl.SSLZeroReturnError as e:
                raise Closed("TLS close_notify") from e
            except ConnectionResetError as e:
                raise Closed("connection reset (RST)") from e
            except ssl.SSLError as e:
                raise Closed("TLS error %s" % e.reason) from e
            if not chunk:
                raise Closed("EOF without TLS close_notify")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def read_frame(self, timeout):
        """(type, flags, stream, payload); raises socket.timeout or Closed."""
        deadline = time.monotonic() + timeout
        head = self._recv_exact(9, deadline)
        length = struct.unpack(">I", b"\0" + head[:3])[0]
        ftype, flags, stream = struct.unpack(">BBI", head[3:])
        payload = self._recv_exact(length, deadline) if length else b""
        return ftype, flags, stream & MAX_WINDOW, payload

    def start(self, initial_window=None, timeout=5.0):
        """Preface and SETTINGS; returns once the server's SETTINGS came."""
        pairs = []
        if initial_window is not None:
            pairs.append((SETTINGS_INITIAL_WINDOW_SIZE, initial_window))
        self.send(PREFACE + settings(pairs))
        deadline = time.monotonic() + timeout
        while True:
            ftype, flags, stream, payload = self.read_frame(
                max(0.01, deadline - time.monotonic()))
            if ftype == SETTINGS and not flags & FLAG_ACK:
                self.send(settings(ack=True))
                return

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
