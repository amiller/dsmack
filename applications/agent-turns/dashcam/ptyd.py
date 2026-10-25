"""Agent-side terminal endpoint: each connection gets a pty running the given command.

Client frames are type (1 byte) + length (4 bytes) + payload: b'd' is input, b'w' is a window
size (rows, cols as two uint16). The server sends the pty's output back unframed.
"""
import fcntl
import os
import pty
import select
import socket
import struct
import sys
import termios
import threading


def serve(conn, argv):
    pid, master = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv)
    buf = b''
    try:
        while True:
            ready, _, _ = select.select([conn, master], [], [])
            if master in ready:
                try:
                    out = os.read(master, 65536)
                except OSError:
                    break
                conn.sendall(out)
            if conn in ready:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
                while len(buf) >= 5 and len(buf) >= 5 + struct.unpack('>I', buf[1:5])[0]:
                    n = struct.unpack('>I', buf[1:5])[0]
                    kind, payload, buf = buf[:1], buf[5:5 + n], buf[5 + n:]
                    if kind == b'd':
                        os.write(master, payload)
                    else:
                        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', *struct.unpack('>HH', payload), 0, 0))
    finally:
        conn.close()
        os.close(master)
        os.waitpid(pid, 0)


def main():
    port, argv = int(sys.argv[1]), sys.argv[2:]
    server = socket.create_server(('0.0.0.0', port))
    while True:
        conn, _ = server.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=serve, args=(conn, argv), daemon=True).start()


if __name__ == '__main__':
    main()
