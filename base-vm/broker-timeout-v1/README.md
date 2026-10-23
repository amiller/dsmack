# Broker timeout compatibility base

This is a new base-image revision, not an update to the previously admitted d9
image. The original pinned sentinel changes exactly two constants: upstream
40→210 seconds and handler 50→220 seconds. Authentication, buffering, the 32 MiB
response cap, 8 MiB request cap, 16 slots and 10-second upstream idle timeout
remain unchanged. The unchanged subscription class inherits these constants.

This permits a continuous 55-second response to finish before the proxy sends
its buffered result. It does **not** implement streaming, fix upstream silence
longer than the socket idle timeout, guarantee provider billing cancellation, or
make `HTTPConnection.close()` interrupt an active response read. Inherited
comments describing hard total ceilings are superseded by these limitations:
the handler closes the client socket at 220 seconds, while an upstream reader
can remain alive until EOF, idle timeout or the native VM's outer 600-second
termination. Continuous responses are bounded by the unchanged 32 MiB byte cap.

The measured guest remains generic; OCI, coding-agent policy and Mac app code
are unchanged. A new rootfs, verity root, metadata and OS image identity are
required. Existing tasks pinning d9 cannot use this image retroactively.

`derive.py` requires an independently selected SOURCE-PINS digest, the complete
original browser-source lock and every selected d9 artifact. It extracts the
parent filesystem, replaces only sentinel.py and its inventory hash row, and
uses the original assembler with image version 0.7.1.broker-timeout-v1. Templates
and kernel remain pinned. Run heavy builds only on Zed `/data` after source
review; never copy private inputs into the build. Output qualification is a
separate gate. The inherited sentinel inventory's historical self-hash is not
claimed as independent authority; measured image identity and selected source
provenance bind the actual bytes.
