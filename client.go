// SPDX-FileCopyrightText: 2026 Asindie, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package nsupp — nsupp /cof/v1 REST API için tipli, bağımlılıksız istemci (stdlib net/http).
// HTTP Basic + X-Cof-Tier auth, {error,data} zarf açma, *Error, web-sitesi kapsamı.
// Kapsanmayan her uç Request() kaçış-kapısıyla erişilebilir.
package nsupp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
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

// SendMessageWithAttachments — content + ek referansları (Crisp attachment parite).
func (w *WebsiteScope) SendMessageWithAttachments(sid, content string, attachments []any) (any, error) {
	return w.Request("POST", "/conversation/"+url.PathEscape(sid)+"/message", &RequestOptions{Body: map[string]any{"content": content, "attachments": attachments}})
}

// AddInternalNote — iç ekip notu (private note; müşteriye gitmez). Scope: website:conversation:notes.
func (w *WebsiteScope) AddInternalNote(sid, content string) (any, error) {
	return w.Request("POST", "/conversation/"+url.PathEscape(sid)+"/note", &RequestOptions{Body: map[string]any{"content": content}})
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
func (w *WebsiteScope) RemoveParticipant(sid, operatorEmail string) (any, error) {
	return w.Request("DELETE", "/conversation/"+url.PathEscape(sid)+"/participants/"+url.PathEscape(operatorEmail), nil)
}

// GetContact — görüşmenin müşteri kişisi (kime yanıt: email/ad/people_id). Scope: website:people:profiles.
func (w *WebsiteScope) GetContact(sid string) (any, error) {
	return w.Request("GET", "/conversation/"+url.PathEscape(sid)+"/contact", nil)
}

// Hazır yanıtlar (composer makroları) — Scope: website:canned
func (w *WebsiteScope) ListCannedReplies() (any, error) {
	return w.Request("GET", "/canned-replies", nil)
}
func (w *WebsiteScope) CreateCannedReply(body map[string]any) (any, error) {
	return w.Request("POST", "/canned-replies", &RequestOptions{Body: body})
}
func (w *WebsiteScope) UpdateCannedReply(id string, body map[string]any) (any, error) {
	return w.Request("PATCH", "/canned-replies/"+url.PathEscape(id), &RequestOptions{Body: body})
}
func (w *WebsiteScope) DeleteCannedReply(id string) (any, error) {
	return w.Request("DELETE", "/canned-replies/"+url.PathEscape(id), nil)
}

// Sipariş notları (eDesk Order notes; at-rest AES-GCM) — Scope: website:orders:notes
func (w *WebsiteScope) ListOrderNotes(connector, order string) (any, error) {
	return w.Request("GET", "/orders/notes", &RequestOptions{Query: map[string]string{"connector": connector, "order": order}})
}
func (w *WebsiteScope) CreateOrderNote(body map[string]any) (any, error) {
	return w.Request("POST", "/orders/notes", &RequestOptions{Body: body})
}
func (w *WebsiteScope) DeleteOrderNote(id string) (any, error) {
	return w.Request("DELETE", "/orders/notes/"+url.PathEscape(id), nil)
}

// People / Helpdesk / Visitors
func (w *WebsiteScope) ListPeople(query map[string]string) (any, error) {
	return w.Request("GET", "/people/profiles", &RequestOptions{Query: query})
}

// UpdatePersonData, kişi özel alanlarını BİRLEŞTİRİR (kısmi güncelleme).
// Tavanlar: istek başına 30, kişi başına 60 anahtar; anahtar <=64, değer (JSON) <=1024 karakter.
// Tavanı aşan anahtar kırpılmaz, DÜŞÜRÜLÜR (sayısı X-Cof-Attributes-Dropped başlığındadır).
// "$..." (nsupp) ve "_..." (operatör) önekli anahtarlar reddedilir.
func (w *WebsiteScope) UpdatePersonData(peopleID string, data map[string]any) (any, error) {
	return w.Request("PATCH", "/people/"+url.PathEscape(peopleID)+"/data", &RequestOptions{Body: data})
}

// ReplacePersonData, kişi özel alanlarını TAM DEĞİŞTİRİR.
// Ayrılmış ("$..."/"_...") anahtarlar KORUNUR — tam değiştirme onları silemez.
func (w *WebsiteScope) ReplacePersonData(peopleID string, data map[string]any) (any, error) {
	return w.Request("PUT", "/people/"+url.PathEscape(peopleID)+"/data", &RequestOptions{Body: data})
}

// Alt kutular (Inbox) — otomatik yönlendirme kuralları dahil.
func (w *WebsiteScope) ListInboxes() (any, error) { return w.Request("GET", "/inboxes", nil) }

// Şeffaflık günlüğü (salt-okur) — scope: website:audit.

// ListAuditEvents, çalışma alanı denetim kaydını okur. YAZMA YOLU YOKTUR — kaydı sistem üretir;
// eklenti yazabilseydi iz sahtelenebilir ve kanıt olmaktan çıkardı. Toplama kapalıysa yanıt
// enabled:false der. Essentials altı planda yalnız en yeni 20 satır döner ve filtreler yok sayılır;
// kayıt SİLİNMEZ, yükseltmede geri gelir.
func (w *WebsiteScope) ListAuditEvents(query map[string]string) (any, error) {
	return w.Request("GET", "/audit", &RequestOptions{Query: query})
}

// Kişisel veri paylaşımı (0179) — scope: website:disclosure.

// GetDisclosure, operatörün müşteriyi doğrulayıp doğrulamadığını ve hangi siparişlerin
// paylaşılabileceğini döndürür. DOĞRULAMA API'de YOKTUR: kapıyı açmak operatörün canlı temasta
// verdiği güven kararıdır (API'den açılabilseydi sipariş-no + e-posta denemeleri sorgulayıcıya dönerdi).
func (w *WebsiteScope) GetDisclosure(sessionID string) (any, error) {
	return w.Request("GET", "/conversation/"+url.PathEscape(sessionID)+"/disclosure", nil)
}

// ShareOrder, doğrulanmış siparişi sohbete KART olarak gönderir (no + durum + kargo + takip linki).
// Kart SUNUCUDA kurulur; gönderdiğiniz alanlar yok sayılır. Kartta alıcı adı/adres/telefon/e-posta
// ASLA bulunmaz. Doğrulanmamışsa 403 "disclosure_unverified".
func (w *WebsiteScope) ShareOrder(sessionID, connectorID, orderNumber string) (any, error) {
	body := map[string]any{"kind": "order", "connector_id": connectorID, "order_number": orderNumber}
	return w.Request("POST", "/conversation/"+url.PathEscape(sessionID)+"/disclosure/share", &RequestOptions{Body: body})
}

// ShareProduct, ürün kartı gönderir — katalog kişisel veri DEĞİL, doğrulama kapısı yoktur.
func (w *WebsiteScope) ShareProduct(sessionID, connectorID, productID string) (any, error) {
	body := map[string]any{"connector_id": connectorID, "product_id": productID}
	return w.Request("POST", "/conversation/"+url.PathEscape(sessionID)+"/share-product", &RequestOptions{Body: body})
}

// Arşiv (0175) — duruma DİK eksen.

// GetConversationState, görüşme durumunu + arşiv bayrağını döndürür.
func (w *WebsiteScope) GetConversationState(sessionID string) (any, error) {
	return w.Request("GET", "/conversation/"+url.PathEscape(sessionID)+"/state", nil)
}

// SetConversationState, durumu ve/veya arşiv bayrağını değiştirir (ikisi tek çağrıda gönderilebilir).
// Arşiv YALNIZ çözülmüş görüşmede geçerlidir (400 "not_resolved"); yeniden açılınca damga OTOMATİK
// temizlenir. body: map[string]any{"state": "resolved", "archived": true}
func (w *WebsiteScope) SetConversationState(sessionID string, body map[string]any) (any, error) {
	return w.Request("PATCH", "/conversation/"+url.PathEscape(sessionID)+"/state", &RequestOptions{Body: body})
}

func (w *WebsiteScope) GetInbox(inboxID string) (any, error) {
	return w.Request("GET", "/inbox/"+url.PathEscape(inboxID), nil)
}

// CreateInbox, alt kutu oluşturur; body["conditions"] ile OTOMATİK yönlendirme kurulur:
//
//	map[string]any{"manual": false, "mode": "and", "rules": []any{
//	    map[string]any{"kind": "data", "key": "plan", "op": "eq", "value": "vip"},
//	    map[string]any{"kind": "sla", "slaWithinDays": 2},
//	}}
//
// kind: email · locale · country · segment · data · sla. "data" kuralı "key" ister
// ("$"/"_" önekleri reddedilir). Birden çok SLA kuralı eşleşirse EN DAR eşik kazanır.
func (w *WebsiteScope) CreateInbox(body map[string]any) (any, error) {
	return w.Request("POST", "/inbox", &RequestOptions{Body: body})
}

// SaveInbox, alt kutuyu günceller (yalnız gönderilen alanlar değişir).
func (w *WebsiteScope) SaveInbox(inboxID string, body map[string]any) (any, error) {
	return w.Request("PUT", "/inbox/"+url.PathEscape(inboxID), &RequestOptions{Body: body})
}

func (w *WebsiteScope) DeleteInbox(inboxID string) (any, error) {
	return w.Request("DELETE", "/inbox/"+url.PathEscape(inboxID), nil)
}
func (w *WebsiteScope) ListArticles() (any, error) {
	return w.Request("GET", "/helpdesk/articles", nil)
}
func (w *WebsiteScope) ListVisitors() (any, error) { return w.Request("GET", "/visitors", nil) }

// VerifyWebhook, bir nsupp Web Hook teslimini doğrular. HMAC-SHA256(`<timestamp>;<payload>`, secret)
// değerini HAM gövde üzerinden yeniden hesaplar, X-Cof-Signature ile sabit-zamanlı karşılaştırır ve
// X-Cof-Request-Timestamp tolerans penceresi dışındaysa reddeder (replay savunması). payload HAM istek
// gövdesi olmalı (JSON'u yeniden ayrıştırıp seri hale getirme). toleranceSec <= 0 ise 300 (5 dk) kullanılır;
// nowMs == 0 ise şu anki zaman (ms) kullanılır. Yalnız her iki kontrol de geçerse true döner.
func VerifyWebhook(payload, signature, timestamp, secret string, toleranceSec int, nowMs int64) bool {
	if toleranceSec <= 0 {
		toleranceSec = 300
	}
	tsNum, err := strconv.ParseInt(strings.TrimSpace(timestamp), 10, 64)
	if err != nil {
		return false
	}
	if nowMs == 0 {
		nowMs = time.Now().UnixMilli()
	}
	diff := nowMs - tsNum
	if diff < 0 {
		diff = -diff
	}
	if diff > int64(toleranceSec)*1000 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + ";" + payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expected))
}
