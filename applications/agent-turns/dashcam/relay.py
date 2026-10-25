"""Terminal relay: joins the user's terminal to the agent's ptyd and records every byte both ways."""
import argparse
import fcntl
import os
import select
import signal
import socket
import struct
import sys
import termios
import tty

from dashcam import Chain


def frame(kind, payload):
    return kind + struct.pack('>I', len(payload)) + payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--agent', default='agent:7000')
    parser.add_argument('--chain', default='/dashcam')
    args = parser.parse_args()
    chain = Chain(args.chain)
    host, port = args.agent.rsplit(':', 1)
    conn = socket.create_connection((host, int(port)))
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    wake_r, wake_w = os.pipe()
    signal.signal(signal.SIGWINCH, lambda *_: os.write(wake_w, b'w'))
    signal.signal(signal.SIGHUP, lambda *_: sys.exit(0))

    def resize():
        rows, cols = struct.unpack('HHHH', fcntl.ioctl(0, termios.TIOCGWINSZ, b'\0' * 8))[:2]
        conn.sendall(frame(b'w', struct.pack('>HH', rows, cols)))
        chain.append('relay', 'resize', meta={'rows': rows, 'cols': cols})

    saved = termios.tcgetattr(0)
    tty.setraw(0)
    try:
        chain.append('relay', 'attach', meta={'agent': args.agent})
        resize()
        while True:
            ready, _, _ = select.select([0, conn, wake_r], [], [])
            if conn in ready:
                out = conn.recv(65536)
                if not out:
                    break
                os.write(1, out)
                chain.append('relay', 'out', out)
            if 0 in ready:
                data = os.read(0, 65536)
                if not data:
                    break
                conn.sendall(frame(b'd', data))
                chain.append('relay', 'in', data)
            if wake_r in ready:
                os.read(wake_r, 64)
                resize()
    finally:
        termios.tcsetattr(0, termios.TCSADRAIN, saved)
        chain.append('relay', 'detach')


if __name__ == '__main__':
    main()
