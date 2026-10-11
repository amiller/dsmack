# Apple trust anchor

Fetched over HTTPS on 2026-09-09 from
https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem

Subject: `CN=Apple App Attestation Root CA, O=Apple Inc., ST=California`

DER SHA-256: `1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932`

The service checks this fingerprint at startup. It neither accepts a root supplied
by the phone nor uses the system's web-PKI roots for App Attest chain validation.
Synthetic roots can be injected only through the Python test API and are labeled
in every verdict. Normal HTTPS server authentication remains separate.
