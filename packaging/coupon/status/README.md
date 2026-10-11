# Public status view

Static assets for a small friend-facing status view. This page does not discover
peers, verify quotes, unlock traces or accept coupons. Serve these reviewed assets
and a separately validated public `health.json` copy together over HTTPS. The
copy must contain only `state`, `observed_at_unix`, `claiming_available` from the
[controller](../public-testnet-operations.md). Never mount its private state
directory in a web server or publish adapter outputs.

Observations expire locally after 90 seconds; future skew over 30 seconds and
fetch/schema failures display unknown. Refresh runs every 30 seconds. The view
labels its source as operator observation and separates claim readiness from
issuer reachability, provider admission and unknown participant counts.

Check with `node --test packaging/coupon/status/test-status.mjs`. Deployment and
the public-copy exporter require the concrete testnet publication review.
