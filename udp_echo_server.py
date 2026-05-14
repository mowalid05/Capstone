"""
udp_echo_server.py — target service for Slot B2 lab.

Owner: A3.

Binds a UDP socket on --port and echoes every datagram back to its source.
Used so the flooder's traffic has a "real" destination service to hit;
the detector sniffs this same interface.
"""

import argparse
import socket


def parse_args() -> argparse.Namespace:
    """CLI: --port (default 9999). Owner: A3."""
    raise NotImplementedError("A3: implement.")


def serve(port: int) -> None:
    """
    Echo loop. Owner: A3.

    1. Create SOCK_DGRAM socket, SO_REUSEADDR=1.
    2. Bind to 0.0.0.0:port.
    3. Forever: data, addr = recvfrom(65535); sock.sendto(data, addr).
    4. Print a one-line summary every N packets so logs show life.
    """
    raise NotImplementedError("A3: implement echo loop.")


def main():
    args = parse_args()
    serve(args.port)


if __name__ == "__main__":
    main()
