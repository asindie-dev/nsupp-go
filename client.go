// Package nsupp — nsupp /cof/v1 REST API için tipli, bağımlılıksız istemci (stdlib net/http).
// HTTP Basic + X-Cof-Tier auth, {error,data} zarf açma, *Error, web-sitesi kapsamı.
// Kapsanmayan her uç Request() kaçış-kapısıyla erişilebilir.
package nsupp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Transport: test/PSR-benzeri enjeksiyon dikişi — (method, url, headers, body) -> (status, respBody, err).
type Transport func(method, url string, headers map[string]string, body []byte) (int, []byte, error)

// Config — istemci yapılandırması.
type Config struct {
	Identifier string
	Secret     string
	Tier       string // "plugin" (varsayılan) | "website"
	BaseURL    string // varsayılan https://api.nsupp.com/cof
	WebsiteID  string
	HTTPClient *http.Client
	Transport  Transport // verilirse HTTPClient yerine kullanılır (test)
}

// Error — API hata zarfından ({error:true,reason,code}) türetilir; errors.As uyumlu.
type Error struct {
	Message string
	Status  int
	Code    string
	Body    []byte
}

func (e *Error) Error() string { return fmt.Sprintf("nsupp: %s (status %d)", e.Message, e.Status) }

// Client — nsupp REST istemcisi.
type Client struct {
	baseURL   string
	auth      string
	tier      string
	websiteID string
	transport Transport
}

// New — bir istemci kurar.
func New(cfg Config) (*Client, error) {
	if cfg.Identifier == "" || cfg.Secret == "" {
		return nil, fmt.Errorf("nsupp: Identifier ve Secret gerekli")
	}
	base := cfg.BaseURL
	if base == "" {
		base = "https://api.nsupp.com/cof"
	}
	tier := cfg.Tier
	if tier == "" {
		tier = "plugin"
	}
	c := &Client{
		baseURL:   strings.TrimRight(base, "/"),
		auth:      "Basic " + base64.StdEncoding.EncodeToString([]byte(cfg.Identifier+":"+cfg.Secret)),
		tier:      tier,
		websiteID: cfg.WebsiteID,
		transport: cfg.Transport,
	}
	if c.transport == nil {
		hc := cfg.HTTPClient
		if hc == nil {
			hc = &http.Client{Timeout: 30 * time.Second}
		}
		c.transport = defaultTransport(hc)
	}
	return c, nil
}

// RequestOptions — istek seçenekleri.
type RequestOptions struct {
	Query map[string]string
	Body  any
	Tier  string
}

// Request — ham istek; zarfı açar, hata zarfında *Error döner. HEAD → (nil, nil) 2xx'te. Tüm uçlar bununla.
func (c *Client) Request(method, path string, opts *RequestOptions) (any, error) {
	u := c.baseURL + path
	tier := c.tier
	var body []byte
	if opts != nil {
		if len(opts.Query) > 0 {
			q := url.Values{}
			for k, v := range opts.Query {
				if v != "" {
					q.Set(k, v)
				}
			}
			if enc := q.Encode(); enc != "" {
				if strings.Contains(u, "?") {
					u += "&" + enc
				} else {
					u += "?" + enc
				}
			}
		}
		if opts.Tier != "" {
			tier = opts.Tier
		}
	}
	method = strings.ToUpper(method)
	headers := map[string]string{"Authorization": c.auth, "X-Cof-Tier": tier}
	if opts != nil && opts.Body != nil && method != "GET" && method != "HEAD" {
		b, err := json.Marshal(opts.Body)
		if err != nil {
			return nil, err
		}
		body = b
		headers["Content-Type"] = "application/json"
	}
	status, respBody, err := c.transport(method, u, headers, body)
	if err != nil {
		return nil, &Error{Message: "network_error: " + err.Error(), Status: 0}
	}
	if method == "HEAD" {
		if status < 200 || status >= 300 {
			return nil, &Error{Message: "not_found", Status: status}
		}
		return nil, nil
	}
	var env map[string]any
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &env); err != nil {
			return nil, &Error{Message: "invalid_response", Status: status, Body: respBody}
		}
	}
	if e, _ := env["error"].(bool); e {
		msg, _ := env["reason"].(string)
		code, _ := env["code"].(string)
		return nil, &Error{Message: msg, Status: status, Code: code, Body: respBody}
	}
	if status < 200 || status >= 300 {
		return nil, &Error{Message: fmt.Sprintf("http_%d", status), Status: status, Body: respBody}
	}
	return env["data"], nil
}

// Website — bir web sitesine (public key) sabitlenmiş tipli kapsam. websiteID boşsa Config.WebsiteID kullanılır.
func (c *Client) Website(websiteID ...string) (*WebsiteScope, error) {
	id := c.websiteID
	if len(websiteID) > 0 && websiteID[0] != "" {
		id = websiteID[0]
	}
	if id == "" {
		return nil, fmt.Errorf("nsupp: websiteID gerekli (veya Config.WebsiteID verin)")
	}
	return &WebsiteScope{client: c, WebsiteID: id}, nil
}

func defaultTransport(hc *http.Client) Transport {
	return func(method, u string, headers map[string]string, body []byte) (int, []byte, error) {
		var r io.Reader
		if body != nil {
			r = bytes.NewReader(body)
		}
		req, err := http.NewRequest(method, u, r)
		if err != nil {
			return 0, nil, err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := hc.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b, nil
	}
}

// WebsiteScope — bir web sitesine sabitlenmiş, en-çok-kullanılan uçların tipli sarmalayıcısı. Kapsanmayan: Request().
type WebsiteScope struct {
	client    *Client
	WebsiteID string
}

func (w *WebsiteScope) p(sub string) string {
	return "/v1/website/" + url.PathEscape(w.WebsiteID) + sub
}

// Request — bu web sitesine sabitlenmiş ham istek.
func (w *WebsiteScope) Request(method, sub string, opts *RequestOptions) (any, error) {
	return w.client.Request(method, w.p(sub), opts)
}

func (w *WebsiteScope) Get() (any, error) { return w.Request("GET", "", nil) }

// Conversations / Conversation
func (w *WebsiteScope) ListConversations(query map[string]string) (any, error) {
	return w.Request("GET", "/conversations", &RequestOptions{Query: query})
}
func (w *WebsiteScope) GetConversation(sid string) (any, error) {
	return w.Request("GET", "/conversation/"+url.PathEscape(sid), nil)
}
func (w *WebsiteScope) GetMessages(sid string) (any, error) {
	return w.Request("GET", "/conversation/"+url.PathEscape(sid)+"/messages", nil)
}
func (w *WebsiteScope) SendMessage(sid, content string) (any, error) {
	return w.Request("POST", "/conversation/"+url.PathEscape(sid)+"/message", &RequestOptions{Body: map[string]any{"content": content}})
}

// Bağlı-kanal teslim-eden yanıtlar (ticket/mail/pazaryeri/yorum)
func (w *WebsiteScope) EmailReply(sid, content string) (any, error) {
	return w.Request("POST", "/conversation/"+url.PathEscape(sid)+"/email-reply", &RequestOptions{Body: map[string]any{"content": content}})
}
func (w *WebsiteScope) MarketplaceReply(sid, content string) (any, error) {
	return w.Request("POST", "/conversation/"+url.PathEscape(sid)+"/marketplace-reply", &RequestOptions{Body: map[string]any{"content": content}})
}
func (w *WebsiteScope) ReviewReply(sid, content string) (any, error) {
	return w.Request("POST", "/conversation/"+url.PathEscape(sid)+"/review-reply", &RequestOptions{Body: map[string]any{"content": content}})
}
func (w *WebsiteScope) AddParticipant(sid, operatorEmail string) (any, error) {
	return w.Request("POST", "/conversation/"+url.PathEscape(sid)+"/participants", &RequestOptions{Body: map[string]any{"operator_email": operatorEmail}})
}

// People / Helpdesk / Visitors
func (w *WebsiteScope) ListPeople(query map[string]string) (any, error) {
	return w.Request("GET", "/people/profiles", &RequestOptions{Query: query})
}
func (w *WebsiteScope) ListArticles() (any, error) {
	return w.Request("GET", "/helpdesk/articles", nil)
}
func (w *WebsiteScope) ListVisitors() (any, error) { return w.Request("GET", "/visitors", nil) }
