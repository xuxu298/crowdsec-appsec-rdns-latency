#!/usr/bin/env python3
"""slow-ptr.py -- a deliberately degraded DNS responder, for reproducing the
condition under test.

NOT RUN BY THE AUTHOR. Like everything else here, this has not been executed
against a live CrowdSec host by whoever published it.

Why a fixture instead of "point it at a flaky resolver and see": a borrowed
failure is not reproducible. If you measure against whatever your upstream
resolver happens to be doing today, you cannot re-run the measurement tomorrow,
and neither can anyone reading your result. This responder makes "slow" and
"SERVFAIL" into knobs with numbers on them.

It is synthetic on purpose. It is not a capture of anyone's production DNS.

Modes:
  --mode servfail   answer with SERVFAIL after --delay-ms
  --mode nxdomain   answer with NXDOMAIN after --delay-ms
  --mode noerror    answer with an empty NOERROR after --delay-ms
  --mode drop       never answer at all, so the client must hit its own timeout

Each query is handled on its own thread. A single-threaded responder would
serialise the delays, and you would end up measuring your fixture's queue depth
instead of the resolver latency you meant to impose.
"""

import argparse
import socketserver
import struct
import sys
import threading
import time

RCODE = {"noerror": 0, "servfail": 2, "nxdomain": 3}

_counter_lock = threading.Lock()
_counter = {"seen": 0, "answered": 0, "dropped": 0}


def build_response(query: bytes, rcode: int) -> bytes:
    """Echo the query back as a response with the given RCODE.

    Only the header is rewritten; the question section is copied verbatim,
    which is all a resolver needs to match the answer to its outstanding query.
    """
    if len(query) < 12:
        raise ValueError("short DNS message")

    txid, flags, qdcount = struct.unpack("!HHH", query[:6])

    rd = flags & 0x0100          # preserve recursion-desired
    opcode = flags & 0x7800      # preserve opcode
    resp_flags = 0x8000 | opcode | rd | 0x0080 | (rcode & 0x000F)

    header = struct.pack("!HHHHHH", txid, resp_flags, qdcount, 0, 0, 0)
    return header + query[12:]


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        opts = self.server.opts

        with _counter_lock:
            _counter["seen"] += 1
            seen = _counter["seen"]

        if opts.delay_ms > 0:
            time.sleep(opts.delay_ms / 1000.0)

        if opts.mode == "drop":
            with _counter_lock:
                _counter["dropped"] += 1
            if opts.verbose:
                print(f"[{seen}] {self.client_address[0]} -> dropped", flush=True)
            return

        try:
            reply = build_response(data, RCODE[opts.mode])
        except ValueError:
            return

        sock.sendto(reply, self.client_address)
        with _counter_lock:
            _counter["answered"] += 1
        if opts.verbose:
            print(
                f"[{seen}] {self.client_address[0]} -> {opts.mode} "
                f"after {opts.delay_ms}ms",
                flush=True,
            )


class Server(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    ap = argparse.ArgumentParser(description="degraded DNS responder")
    ap.add_argument("--listen", default="127.0.0.1:5353",
                    help="host:port to bind (default 127.0.0.1:5353)")
    ap.add_argument("--delay-ms", type=int, default=2500,
                    help="delay before responding, in ms (default 2500)")
    ap.add_argument("--mode", default="servfail",
                    choices=["servfail", "nxdomain", "noerror", "drop"],
                    help="what to answer with (default servfail)")
    ap.add_argument("--verbose", action="store_true", help="log every query")
    opts = ap.parse_args()

    if ":" not in opts.listen:
        print("--listen must be host:port", file=sys.stderr)
        return 2
    host, _, port_s = opts.listen.rpartition(":")
    try:
        port = int(port_s)
    except ValueError:
        print(f"bad port: {port_s!r}", file=sys.stderr)
        return 2

    if opts.delay_ms < 0:
        print("--delay-ms must be >= 0", file=sys.stderr)
        return 2

    server = Server((host, port), Handler)
    server.opts = opts

    print(f"listening   : udp {host}:{port}")
    print(f"mode        : {opts.mode}")
    print(f"delay       : {opts.delay_ms}ms")
    print("")
    print("Point the CrowdSec host's resolver here, restart crowdsec, then run")
    print("measure.sh. Revert the resolver change when you are finished.")
    print("")
    print("Ctrl-C to stop.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
        with _counter_lock:
            print("")
            print(f"queries seen     : {_counter['seen']}")
            print(f"queries answered : {_counter['answered']}")
            print(f"queries dropped  : {_counter['dropped']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
