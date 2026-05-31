import argparse
import socket


def parse_args() -> argparse.Namespace:
    # reads --port from the command line
    # example: python udp_echo_server.py --port 9999
    parser = argparse.ArgumentParser(description="UDP echo server.")
    parser.add_argument("--port", type=int, default=9999, help="Port to listen on (default: 9999).")
    return parser.parse_args()


def serve(port: int) -> None:
    # opens a UDP socket and sends every packet back to whoever sent it

    # SOCK_DGRAM means UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # SO_REUSEADDR lets us restart without "address already in use" error
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # 0.0.0.0 means listen on all network interfaces inside the container
    sock.bind(("0.0.0.0", port))
    print(f"[ECHO] Listening on port {port} — press Ctrl+C to stop.")

    total_packets = 0
    total_bytes   = 0

    while True:
        try:
            # recvfrom returns the data and the sender's address
            data, addr = sock.recvfrom(65535)

            # send the same data back to the sender
            sock.sendto(data, addr)

            total_packets += 1
            total_bytes   += len(data)

            # print a summary line every 100 packets so we can see it is working
            if total_packets % 100 == 0:
                print(f"[ECHO] {total_packets} packets echoed ({total_bytes} bytes) — last from {addr[0]}:{addr[1]}")

        except KeyboardInterrupt:
            print(f"\n[ECHO] Stopped. Total: {total_packets} packets, {total_bytes} bytes.")
            break

        except OSError as err:
            print(f"[ECHO] Error: {err}")
            break

    sock.close()


def main():
    args = parse_args()
    serve(args.port)


if __name__ == "__main__":
    main()
