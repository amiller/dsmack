"""Keystroke echo latency: run a terminal command in a pty, type one byte, time the first output byte.

usage: latency.py N -- command...
"""
import os
import pty
import select
import statistics
import sys
import time


def drain(fd, quiet):
    while select.select([fd], [], [], quiet)[0]:
        os.read(fd, 65536)


def main():
    n, argv = int(sys.argv[1]), sys.argv[sys.argv.index('--') + 1:]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv)
    drain(fd, 2.0)
    samples = []
    for _ in range(n):
        start = time.perf_counter()
        os.write(fd, b'a')
        select.select([fd], [], [])
        samples.append((time.perf_counter() - start) * 1000)
        drain(fd, 0.03)
    os.write(fd, b'\x15exit\r')
    samples.sort()
    print('n=%d median=%.2fms p90=%.2fms p99=%.2fms' % (
        n, statistics.median(samples), samples[int(n * .9)], samples[int(n * .99)]))


if __name__ == '__main__':
    main()
