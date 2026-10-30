# Recovery email receiver

This receive-only SMTP sink and raw-message HTTP endpoint retain the original
headers under the subject nonce for fifteen minutes. Message bodies are discarded
while streaming. Exim pipe input may use LF line endings and a leading mbox
`From ` envelope line; the receiver removes that envelope and restores CRLF
without changing header values. The attested email gate verifies the headers
before releasing keys.

Run the local test mailbox with Node 22 or newer:

```sh
RECOVERY_ADDRESS=recover@example.test SMTP_PORT=2525 HTTP_PORT=8788 node run.mjs
node --test receiver.test.mjs
```

Deliver an RFC 822 message through SMTP on localhost:2525, or POST it to
`http://localhost:8788/email-recovery/inbound` with Content-Type `message/rfc822`.
The subject is `dsmack-recover <26-character-base32-nonce>`. Poll
`/email-recovery/headers/<nonce>`: 202 means pending; 200 returns
`{nonce,headers,expiresAt}`. Responses use Cache-Control: no-store.

For the deployed page, route `/email-recovery/` to one `HeaderReceiver` instance
in `server.ts`. A separate SMTP process can deliver into that instance by setting
`INBOUND_URL=https://private-agent.dstack.soc1024.com/email-recovery/inbound`.
`RECOVERY_ADDRESS` selects its sole accepted SMTP recipient; `RECEIVER_HOST`
selects the bind interface. SIGTERM stops both listeners. The receiver has no
mailbox, account credentials or outbound SMTP capability.

Connect a real address by configuring its existing inbound forwarder to submit
the unchanged raw message to the HTTPS inbound URL above. This is the recommended
option because it uses the existing HTTPS ingress. An SMTP forwarder can instead
send to the SMTP listener after its port is exposed; a direct MX also needs public
port 25 and DNS. Preserve DKIM-Signature, From, Date and Subject without rewriting.
