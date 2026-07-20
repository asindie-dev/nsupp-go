# nsupp REST SDK — Go

Typed, dependency-free client for the **nsupp `/cof/v1` REST API** (stdlib `net/http` only).

Handles HTTP Basic auth + `X-Cof-Tier`, unwraps the `{ error, data }` envelope, returns an `*Error` (`errors.As`-friendly) on failures, and gives you a website-scoped helper. Every endpoint is reachable — common ones as methods, the rest via `Request()`.

## Install

```bash
go get posthubify/nsupp-rest
```

## Quickstart

```go
import (
    "errors"
    nsupp "posthubify/nsupp-rest"
)

client, _ := nsupp.New(nsupp.Config{
    Identifier: os.Getenv("NSUPP_IDENTIFIER"), // nsupp_pk_…
    Secret:     os.Getenv("NSUPP_SECRET"),
    Tier:       "plugin",
    WebsiteID:  "8f3c1d…",
    // BaseURL: "https://api.nsupp.com/cof",
})

site, _ := client.Website()

website, _ := site.Get()
convos, _ := site.ListConversations(map[string]string{"page": "1"})
site.SendMessage("session_1", "Hi 👋 — how can we help?")

// Connected-channel delivering replies (ticket / mail / marketplace / review):
site.EmailReply("session_1", "Thanks — your order ships today.")
site.MarketplaceReply("session_2", "It ships within 24 hours.")
site.ReviewReply("session_3", "Thank you for the feedback!")

if _, err := site.GetConversation("missing"); err != nil {
    var ne *nsupp.Error
    if errors.As(err, &ne) {
        log.Printf("%d %s %s", ne.Status, ne.Code, ne.Message)
    }
}

// Escape hatch — any endpoint:
site.Request("POST", "/helpdesk/article/a_1/alternate", &nsupp.RequestOptions{Body: map[string]any{"alternate_article_id": "a_2"}})
```

Run the tests: `go test ./...`.
