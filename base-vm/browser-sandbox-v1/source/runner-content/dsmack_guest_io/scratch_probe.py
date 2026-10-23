"""Trusted in-guest sampled scratch accounting; no instantaneous peak claim."""
import fcntl
import json
import os
import signal
import struct
import time

class Samples:
    def __init__(self):
        self.count = 0
        self.total = None
        self.min_free = None
        self.min_available = None
    def add(self, value):
        total = value.f_blocks * value.f_frsize
        free = value.f_bfree * value.f_frsize
        available = value.f_bavail * value.f_frsize
        if not 0 <= available <= free <= total or (self.total is not None and self.total != total):
            raise ValueError('inconsistent scratch capacity')
        self.total = total
        self.min_free = free if self.min_free is None else min(self.min_free, free)
        self.min_available = available if self.min_available is None else min(self.min_available, available)
        self.count += 1
    def body(self, device_bytes, reason):
        if self.count == 0 or self.total > device_bytes:
            raise ValueError('missing/invalid samples')
        return dict(schema='dsmack.scratch-samples/1', device_bytes=device_bytes,
                    filesystem_bytes=self.total, minimum_free_bytes=self.min_free,
                    minimum_available_bytes=self.min_available,
                    sampled_peak_used_bytes=self.total-self.min_free,
                    samples=self.count, requested_interval_seconds=0.1, termination=reason)

def main():
    stopped = False
    def stop(*_):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop)
    fd = os.open('/dev/vdb', os.O_RDONLY | os.O_CLOEXEC)
    try:
        device_bytes = struct.unpack('Q', fcntl.ioctl(fd, 0x80081272, b'\0'*8))[0]
    finally:
        os.close(fd)
    if device_bytes != 1073741824:
        raise ValueError('selected Mini scratch capacity differs')
    samples = Samples()
    deadline = time.monotonic()+3600
    while not stopped and time.monotonic() < deadline:
        samples.add(os.statvfs('/var/lib/docker'))
        time.sleep(0.1)
    print(json.dumps(samples.body(device_bytes, 'stopped' if stopped else 'deadline'),sort_keys=True,separators=(',',':')),flush=True)

if __name__ == '__main__':
    main()
