# Decisions

One short file per design decision: `NNNN-title-with-dashes.md`, copied from
[template.md](template.md). A decision that changes an earlier one names it in
`builds-on`, and the earlier one's status becomes `superseded by NNNN`.

| # | Decision | Status |
|---|---|---|
| [0001](0001-agent-loop-in-browser.md) | The agent loop runs in the browser; the guest only runs tools | accepted |
| [0002](0002-browser-encrypted-inference.md) | Model calls are encrypted in the browser to a NEAR TEE model | accepted |
| [0003](0003-chats-stay-in-browser.md) | Chats live in the browser and sync encrypted under the wallet | accepted |
| [0004](0004-no-plaintext-reports.md) | Failure reports never carry conversation content | accepted |
| [0005](0005-dstack-guest-api.md) | The Mac guest offers dstack's guest API | accepted |
