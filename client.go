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
	"errors"
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
	// AccessToken — OAuth USER access token (`POST /v1/oauth/token`). Sent as
	// `Authorization: Bearer …` (RFC 6750); NO `X-Cof-Tier` header is sent, because the Bearer
	// scheme already says what the credential is and a proprietary header would break every
	// standard OAuth client. A user token reaches only the workspaces the consenting person
	// belongs to AND your app is installed in, carries the scopes that person consented to, and
	// stops working the moment they revoke your app. Use this OR Identifier+Secret.
	AccessToken string
	Tier        string // "plugin" (varsayılan) | "website"
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
	bearer    bool
	tier      string
	websiteID string
	transport Transport
}

// New — bir istemci kurar.
func New(cfg Config) (*Client, error) {
	if cfg.AccessToken == "" && (cfg.Identifier == "" || cfg.Secret == "") {
		return nil, fmt.Errorf("nsupp: pass either AccessToken (OAuth user token) or Identifier + Secret")
	}
	base := cfg.BaseURL
	if base == "" {
		base = "https://api.nsupp.com/cof"
	}
	tier := cfg.Tier
	if tier == "" {
		tier = "plugin"
	}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(cfg.Identifier+":"+cfg.Secret))
	if cfg.AccessToken != "" {
		auth = "Bearer " + cfg.AccessToken
	}
	c := &Client{
		baseURL:   strings.TrimRight(base, "/"),
		auth:      auth,
		bearer:    cfg.AccessToken != "",
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
	headers := map[string]string{"Authorization": c.auth}
	if !c.bearer {
		headers["X-Cof-Tier"] = tier
	}
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
		return nil, fmt.Errorf("nsupp: websiteID is required (or set Config.WebsiteID)")
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
// GetMessages, bir konuşmanın mesajlarını döner. İmleç ÇİFTTİR: before (en eski mesajın
// timestamp'i) + before_id (aynı mesajın fingerprint'i) — yalnız damga aynı ms'deki mesajı atlar.
func (w *WebsiteScope) GetMessages(sid string, query map[string]string) (any, error) {
	return w.Request("GET", "/conversation/"+url.PathEscape(sid)+"/messages", &RequestOptions{Query: query})
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

// Ekip sohbeti — scope: website:team:chat.

// ListTeamChatMessages, ekibin GENEL kanalını okur. KAPSAM BİLEREK DAR: özel gruplar ve birebir
// mesajlar API'de YOKTUR — o kanalların üyeliği KİŞİ kimliğine bağlıdır, API anahtarının arkasında
// kişi yoktur. Silinen mesaj yerinde kalır (content boş, deleted true) — akışta delik açılmaz.
//
// Sayfalama imleci ISO damgadır: "after" ileri (poll), "before" geriye (geçmiş) yürür. Bir sonraki
// "before" = önceki sayfanın en eski created_at'i; sayfa limit'ten kısaysa başa ulaşılmıştır.
func (w *WebsiteScope) ListTeamChatMessages(query map[string]string) (any, error) {
	return w.Request("GET", "/team-chat", &RequestOptions{Query: query})
}

// PostTeamChatMessage, genel ekip kanalına mesaj yazar (ziyaretçiye GİTMEZ). Yazar adı eklenti
// kimliğinden gelir, gövdeden değil: bir eklenti kendini başka bir uygulama ya da bir operatör
// gibi gösteremez.
func (w *WebsiteScope) PostTeamChatMessage(content string) (any, error) {
	return w.Request("POST", "/team-chat", &RequestOptions{Body: map[string]any{"content": content}})
}

// PostTeamChannelMessage, belirli bir KANALA yazar. Uygulaman o kanalın ÜYESİ olmalıdır
// ("not_in_channel"); genel kanal tek istisnadır. "website:team:chat:public" scope'uyla AÇIK
// kanallara üyeliksiz de yazılır — özel kanal yine üyelik ister. Gövdeye "blocks" koyarsan düğme
// çizilir; "post_at" mesajı kuyruğa alır (en çok 120 gün) ve scheduled_id döner. Kanal başına
// yaklaşık saniyede bir yazma sınırı vardır; aşılırsa 429 + Retry-After gelir.
func (w *WebsiteScope) PostTeamChannelMessage(channelID string, body map[string]any) (any, error) {
	return w.Request("POST", "/team-chat/channels/"+url.PathEscape(channelID)+"/messages", &RequestOptions{Body: body})
}

// SendTeamDirectMessage, bir KİŞİYE uygulama olarak DM yazar. DM kimliği ÜYE KÜMESİNDEN türediği
// için tek çağrı yeter (Slack iki çağrı ister). Bota DM yazılamaz: iki otomasyonun birbirine yanıt
// vermesi bir döngüdür, özellik değil.
func (w *WebsiteScope) SendTeamDirectMessage(userID, content string) (any, error) {
	return w.Request("POST", "/team-chat/dm", &RequestOptions{Body: map[string]any{"user_id": userID, "content": content}})
}

// SetAgentThread sets the agent surface of one DM: title, transient status line, suggested prompts.
// Partial update: put ONLY the keys you want to change into patch. A nil value CLEARS a field;
// leaving the key out leaves it alone — if those meant the same thing, taking a status line back
// down would be impossible.
func (w *WebsiteScope) SetAgentThread(channelID string, patch map[string]any) (any, error) {
	return w.Request("POST", "/team-chat/assistant/"+url.PathEscape(channelID), &RequestOptions{Body: patch})
}

// ListTeamLists returns the lists in this account. A list is a small database — rows with typed
// UseTeamCanvasTemplate copies a TEMPLATE canvas into a new, independent canvas: title and
// blocks only. Shares are not carried over and the copy is not itself a template.
func (w *WebsiteScope) UseTeamCanvasTemplate(docID string) (any, error) {
	return w.Request("POST", "/team-chat/docs/"+url.PathEscape(docID)+"/use-template", nil)
}

// ShareTeamCanvas opens a canvas to a channel. Apps share with a CHANNEL only - a person-share
// would decide something on that person's behalf and there is no person behind an API key.
func (w *WebsiteScope) ShareTeamCanvas(docID string, body map[string]any) (any, error) {
	return w.Request("POST", "/team-chat/docs/"+url.PathEscape(docID)+"/shares", &RequestOptions{Body: body})
}

// CreateTeamCanvas creates a canvas. There is no "create a file" call: the files plane is a
// union, so you create a canvas - or a list, which has its own endpoint.
func (w *WebsiteScope) CreateTeamCanvas(body map[string]any) (any, error) {
	return w.Request("POST", "/team-chat/docs", &RequestOptions{Body: body})
}

// GetTeamFile returns the details of one file (the info card). Visibility comes from the files
// plane itself, so a file you cannot see answers 404. No size/sha: the plane does not store them
// and a canvas or list has no bytes at all.
func (w *WebsiteScope) GetTeamFile(fileID string) (any, error) {
	return w.Request("GET", "/team-chat/files/"+url.PathEscape(fileID), nil)
}

// CopyTeamCanvas copies a canvas into a NEW, independent document. Seeing it is enough; shares,
// access level, template flag, channel and cover are NOT carried over.
func (w *WebsiteScope) CopyTeamCanvas(docID string) (any, error) {
	return w.Request("POST", "/team-chat/docs/"+url.PathEscape(docID)+"/copy", nil)
}

// DeleteTeamCanvas deletes a canvas. Requires edit access; comments, reactions, versions, shares
// and stars go with it and it cannot be undone.
func (w *WebsiteScope) DeleteTeamCanvas(docID string) (any, error) {
	return w.Request("DELETE", "/team-chat/docs/"+url.PathEscape(docID), nil)
}

// ListTeamCanvasVersions returns the version history, newest first. The list carries NO bodies -
// fetch the one you need with GetTeamCanvasVersion. restored_from marks a restore.
func (w *WebsiteScope) ListTeamCanvasVersions(docID string) (any, error) {
	return w.Request("GET", "/team-chat/docs/"+url.PathEscape(docID)+"/versions", nil)
}

// GetTeamCanvasVersion returns one version with its full body.
func (w *WebsiteScope) GetTeamCanvasVersion(docID, versionID string) (any, error) {
	return w.Request("GET", "/team-chat/docs/"+url.PathEscape(docID)+"/versions/"+url.PathEscape(versionID), nil)
}

// ListTeamCanvasComments returns every comment on a canvas, oldest first. Comments hang off a
// BLOCK, not the document - key your mirror on block_id.
func (w *WebsiteScope) ListTeamCanvasComments(docID string) (any, error) {
	return w.Request("GET", "/team-chat/docs/"+url.PathEscape(docID)+"/comments", nil)
}

// CommentOnTeamCanvasBlock comments on one block. READ access is enough - commenting does not
// change the document. The block must exist in the body, otherwise 404 block_not_found.
func (w *WebsiteScope) CommentOnTeamCanvasBlock(docID, blockID string, body map[string]any) (any, error) {
	return w.Request("POST", "/team-chat/docs/"+url.PathEscape(docID)+"/blocks/"+url.PathEscape(blockID)+"/comments", &RequestOptions{Body: body})
}

// SetTeamCanvasCover sets (or removes) the canvas cover image. The image is NOT uploaded here:
// upload it first and pass the resulting URL. Only a URL from your own account is accepted -
// a cover republishes that file inside your canvas. Pass nil to remove it (object deleted too).
func (w *WebsiteScope) SetTeamCanvasCover(docID string, coverURL *string) (any, error) {
	return w.Request("PUT", "/team-chat/docs/"+url.PathEscape(docID)+"/cover", &RequestOptions{Body: map[string]any{"cover_url": coverURL}})
}

// GetTeamCanvas reads a canvas. The body is an ARRAY OF BLOCKS with stable ids, not one blob of
// HTML: comments and reactions attach to a block, so ids have to survive edits around them.
func (w *WebsiteScope) GetTeamCanvas(docID string) (any, error) {
	return w.Request("GET", "/team-chat/docs/"+url.PathEscape(docID), nil)
}

// UpdateTeamCanvas replaces title, body or both. The body you send is the WHOLE body - keep the
// ids of blocks you did not touch, or the comments attached to them lose their anchor.
func (w *WebsiteScope) UpdateTeamCanvas(docID string, body map[string]any) (any, error) {
	return w.Request("PUT", "/team-chat/docs/"+url.PathEscape(docID), &RequestOptions{Body: body})
}

// ListTeamFiles returns the files this app can see: lists plus attachments on messages in
// channels the app can see. There is no separate file store — a file disappears exactly when the
// list or message holding it does. Newest first; page with after + after_id.
func (w *WebsiteScope) ListTeamFiles(query map[string]string) (any, error) {
	return w.Request("GET", "/team-chat/files", &RequestOptions{Query: query})
}

// columns — not a to-do.
func (w *WebsiteScope) ListTeamLists() (any, error) {
	return w.Request("GET", "/team-chat/lists", nil)
}

// CreateTeamList creates an empty list. Give it columns next: a list with no columns is a table
// with no shape, so nothing can be written into it yet.
func (w *WebsiteScope) CreateTeamList(body map[string]any) (any, error) {
	return w.Request("POST", "/team-chat/lists", &RequestOptions{Body: body})
}

// AddTeamListField adds one typed column. Reusing a key answers 409 rather than overwriting, so
// data already under a column can never be hidden.
//
// A select column's options are objects carrying colour —
// {"value": "in_progress", "label": "In progress", "color": "purple"}. The cell stores the value,
// so renaming an option never strands old rows; the colour comes from a closed palette
// (default "gray") because free hex cannot guarantee a readable chip in both themes.
func (w *WebsiteScope) AddTeamListField(listID string, body map[string]any) (any, error) {
	return w.Request("POST", "/team-chat/lists/"+url.PathEscape(listID)+"/fields", &RequestOptions{Body: body})
}

// StreamTeamMessage appends text to a message posted with stream: true. Send ONLY the new chunk —
// the append happens on our side, because read-modify-write from your side loses a chunk whenever
// two arrive close together. Always finish with done: true, including on your own error paths.
func (w *WebsiteScope) StreamTeamMessage(messageID string, patch map[string]any) (any, error) {
	return w.Request("POST", "/team-chat/messages/"+url.PathEscape(messageID)+"/stream", &RequestOptions{Body: patch})
}

// PostTeamEphemeral, YALNIZ BİR KİŞİNİN gördüğü bir mesaj yazar. İki taraf da kanalda olmalıdır:
// göremediği bir kanalın İÇİNDE birine mesaj göstermek, o kanalın varlığını sızdırırdı.
func (w *WebsiteScope) PostTeamEphemeral(channelID, userID, content string) (any, error) {
	return w.Request("POST", "/team-chat/channels/"+url.PathEscape(channelID)+"/ephemeral",
		&RequestOptions{Body: map[string]any{"user_id": userID, "content": content}})
}

// UpdateTeamChatMessage, KENDİ yazdığın mesajı düzenler. Başkasının mesajı 403 döner — bir
// otomasyonun insanın sözünü değiştirmesi geçmişi sessizce yeniden yazmaktır.
func (w *WebsiteScope) UpdateTeamChatMessage(messageID, content string) (any, error) {
	return w.Request("PATCH", "/team-chat/"+url.PathEscape(messageID), &RequestOptions{Body: map[string]any{"content": content}})
}

// DeleteTeamChatMessage, KENDİ mesajını siler. Arşivli kanalda düzenleme kapalıdır ama silme açıktır.
func (w *WebsiteScope) DeleteTeamChatMessage(messageID string) (any, error) {
	return w.Request("DELETE", "/team-chat/"+url.PathEscape(messageID), nil)
}

// OpenTeamView, tıklamadan gelen trigger_id ile bir pencere açar. Tetikleyici GÖNDERİLDİKTEN
// 3 SANİYE sonra ölür: bunu, tıklamayı 200 ile yanıtlamadan ÖNCE çağır. Pencerenin içeriği SENİN
// sayfandır (iframe), bir görünüm JSON'u değil.
func (w *WebsiteScope) OpenTeamView(triggerID string, view map[string]any) (any, error) {
	return w.Request("POST", "/team-chat/views/open", &RequestOptions{Body: map[string]any{"trigger_id": triggerID, "view": view}})
}

// PublishTeamAppHome, bir kişinin App Home sekmesini yayınlar. Görünüm KİŞİ BAŞINADIR ve en çok
// 100 blok taşır; boş bir blok dizisi sekmeyi temizler.
func (w *WebsiteScope) PublishTeamAppHome(userID string, blocks []any) (any, error) {
	return w.Request("POST", "/team-chat/views/publish", &RequestOptions{
		Body: map[string]any{"user_id": userID, "view": map[string]any{"type": "home", "blocks": blocks}},
	})
}

// ListTeamChatChannels, uygulamanın görebildiği ekip kanallarını listeler (Slack
// conversations.list karşılığı). Üyesi olunan her kanal + genel kanal (üyelik örtük) +
// website:team:chat:public onaylıysa açık kanallar; birebir mesajlar HİÇBİR koşulda listelenmez.
func (w *WebsiteScope) ListTeamChatChannels(query map[string]string) (any, error) {
	return w.Request("GET", "/team-chat/channels", &RequestOptions{Query: query})
}

// GetTeamChatChannel, tek bir ekip kanalının bilgisini döner (Slack conversations.info).
// Göremediğin kanal 404'tür.
func (w *WebsiteScope) GetTeamChatChannel(channelID string) (any, error) {
	return w.Request("GET", "/team-chat/channels/"+url.PathEscape(channelID), nil)
}

// SearchTeamChat, ekip mesajlarında arar (çok kanallı; sonuç hangi kanalda olduğunu taşır).
func (w *WebsiteScope) SearchTeamChat(query map[string]string) (any, error) {
	return w.Request("GET", "/team-chat/search", &RequestOptions{Query: query})
}

// ListTeamChatReplies, bir mesajın thread yanıtlarını döndürür.
func (w *WebsiteScope) ListTeamChatReplies(messageID string) (any, error) {
	return w.Request("GET", "/team-chat/"+url.PathEscape(messageID)+"/replies", nil)
}

// PostTeamChatReply, thread'e yanıt yazar.
func (w *WebsiteScope) PostTeamChatReply(messageID, content string) (any, error) {
	return w.Request("POST", "/team-chat/"+url.PathEscape(messageID)+"/replies", &RequestOptions{Body: map[string]any{"content": content}})
}

// ReactToTeamChatMessage, tepki ekler/kaldırır. Emoji KODU gönderilir ("white_check_mark"), karakter değil.
func (w *WebsiteScope) ReactToTeamChatMessage(messageID, emoji string) (any, error) {
	return w.Request("POST", "/team-chat/"+url.PathEscape(messageID)+"/reactions", &RequestOptions{Body: map[string]any{"emoji": emoji}})
}

// PinTeamChatMessage, mesajı sabitler / sabitlemeyi kaldırır.
func (w *WebsiteScope) PinTeamChatMessage(messageID string) (any, error) {
	return w.Request("POST", "/team-chat/"+url.PathEscape(messageID)+"/pin", nil)
}

// ForwardTeamChatMessage, mesajı başka bir kanala iletir.
func (w *WebsiteScope) ForwardTeamChatMessage(messageID string, body map[string]any) (any, error) {
	return w.Request("POST", "/team-chat/"+url.PathEscape(messageID)+"/forward", &RequestOptions{Body: body})
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

// CanonicalIdentityEmail, kimlik imzalamadan önce uygulanan KANONİK e-posta biçimini üretir:
// ① baştan/sondan şu baytlar atılır: space \t \n \r \v \f · ② YALNIZ A-Z (0x41-0x5A) → a-z (0x61-0x7A).
// Başka HİÇBİR bayt değişmez; e-posta UTF-8'dir ve ASCII-dışı baytlar olduğu gibi korunur.
//
// NİÇİN KANONİKLEŞTİRME: aynı kullanıcının e-postası site tarafında farklı yazımlarla gelir (form
// girişi, OAuth profili, DB kaydı). İmzayı ham metne bağlamak "Jane@Acme.com" ile imzalayıp
// "jane@acme.com" gönderen entegrasyonu SESSİZCE kırıyordu.
//
// NİÇİN strings.ToLower / strings.TrimSpace DEĞİL — SADELEŞTİRMEYİN, KIRARSINIZ: bu imzayı BİZ
// doğrularız ama BAŞKA diller üretir, yani kural her uygulamada BAYT BAYT aynı sonucu vermek
// zorunda. Unicode küçültme bunu sağlamıyor; ölçüldü: 'İSTANBUL@X.com' → JS/Python "i̇stanbul@x.com"
// (i + U+0307) · Go "istanbul@x.com" (düz i) · PHP "İstanbul@x.com" (hiç değişmedi). Unicode kırpma
// da aynı dertte (PHP trim yalnız ASCII boşluk atar). Bu yüzden kapsam ASCII ile SINIRLIDIR ve
// uygulama bayt düzeyinde açıkça yazılır. DÜRÜST SINIR: 'Ömer@x.com' → 'Ömer@x.com' (Ö korunur) —
// belirlenebilirlik, kapsamdan önce gelir.
func CanonicalIdentityEmail(email string) string {
	isTrimByte := func(c byte) bool {
		return c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d || c == 0x0b || c == 0x0c
	}
	b := []byte(email)
	start, end := 0, len(b)
	for start < end && isTrimByte(b[start]) {
		start++
	}
	for end > start && isTrimByte(b[end-1]) {
		end--
	}
	out := make([]byte, end-start)
	copy(out, b[start:end])
	for i, c := range out {
		if c >= 0x41 && c <= 0x5a {
			out[i] = c + 32
		}
	}
	return string(out)
}

// SignIdentity, giriş yapmış kullanıcının e-postasını çalışma-alanı kimlik anahtarıyla imzalar:
// HMAC-SHA256(CanonicalIdentityEmail(email), secret) → küçük harf hex. Widget bu imzayı e-postayla
// birlikte gönderir; nsupp aynı hesabı yapıp sabit-zamanlı karşılaştırır, böylece anonim ziyaretçi
// başkasının kimliğini SAHTELEYEMEZ.
//
// Gizli anahtar tarayıcıya ASLA konmaz (JS'e gömmek, HTML'e basmak, ön-uca uç açmak dahil) — sızarsa
// herkes herkesin kimliğini imzalar. İmza YALNIZ sizin sunucunuzda, oturumdan okunan e-posta ile
// üretilir; anahtar loglanmaz.
//
// FAIL-CLOSED: boş e-posta İMZALANMAZ, hata döner. SignIdentity("") geçerli GÖRÜNEN bir hex
// döndürüyordu; oturumda e-posta boşsa hiçbir yerde hata çıkmaz, imza sayfaya gider ve kimlik ASLA
// doğrulanmaz (sunucu e-postasız iddiayı zaten reddeder). Sessiz çıkmaz — bu yardımcının önlemek
// için var olduğu hata sınıfının ta kendisi.
func SignIdentity(email, secret string) (string, error) {
	canonical := CanonicalIdentityEmail(email)
	if canonical == "" {
		return "", errors.New("nsupp: SignIdentity: email is empty — nothing to sign; read it from the logged-in session before calling")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// SignIdentityJwtOptions, SignIdentityJwt için isteğe bağlı ayarlar.
type SignIdentityJwtOptions struct {
	// TTLSeconds, token ömrü (varsayılan 3600). Kısa tutun — JWT'nin bütün anlamı budur.
	TTLSeconds int
	// Name, GÜVENİLİR görünen ad. Tarayıcıdan gelen addan farkı: bu imzalıdır.
	Name string
	// Attributes, GÜVENİLİR ziyaretçi öznitelikleri (plan, segments, sipariş sayısı…).
	// `$`/`_` ile başlayan anahtarlar sunucunun kendi güven işaretlerine ayrılmıştır ve düşer.
	Attributes map[string]any
	// Now, "şimdi"yi geçersiz kılar. YALNIZ testler için.
	Now time.Time
}

// SignIdentityJwt, giriş yapmış kullanıcının kimliğini KISA ÖMÜRLÜ bir HS256 JWT olarak imzalar.
//
// SignIdentity YERİNE NİÇİN BU: düz HMAC imzası e-postanın SAF bir fonksiyonudur — son-kullanma
// tarihi yoktur, oturuma/cihaza bağlı değildir. Bir kez sızarsa o kişi olarak SONSUZA DEK ve HER
// cihazdan davranılabilir; iptalin tek yolu çalışma alanının anahtarını döndürmek, yani BÜTÜN
// kullanıcıları aynı anda kırmak. JWT `exp` taşır: sızan token kendiliğinden ölür.
//
// İkinci kazanç güvendir: token'daki Name ve Attributes SİZİN backend'inizde imzalanır. Tarayıcıdan
// gelen öznitelik yalnız bir İDDİA'dır — doğrulanmış bir ziyaretçi bile segments:["vip"] iddia edip
// öncelikli kuyruğa girebilir. İmzalı olan taklit EDİLEMEZ.
//
// Çalışma alanı 'hmac' (geçiş) kipindeyken iki biçim de kabul edilir; sayfa sayfa geçebilirsiniz.
// Geçiş bitince kipi 'jwt' yapın — süresiz imzaları kabul etmeyi asıl o durdurur.
//
// FAIL-CLOSED: boş e-posta İMZALANMAZ (SignIdentity ile aynı kural).
func SignIdentityJwt(email, secret string, opts *SignIdentityJwtOptions) (string, error) {
	canonical := CanonicalIdentityEmail(email)
	if canonical == "" {
		return "", errors.New("nsupp: SignIdentityJwt: email is empty — nothing to sign; read it from the logged-in session before calling")
	}
	if opts == nil {
		opts = &SignIdentityJwtOptions{}
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	ttl := opts.TTLSeconds
	if ttl < 1 {
		ttl = 3600
	}
	claims := map[string]any{
		"sub": canonical,
		"iat": now.Unix(),
		"exp": now.Unix() + int64(ttl),
	}
	if n := strings.TrimSpace(opts.Name); n != "" {
		claims["name"] = n
	}
	if len(opts.Attributes) > 0 {
		attrs := map[string]any{}
		for k, v := range opts.Attributes {
			key := strings.TrimSpace(k)
			// Sessizce göndermek "ayarladım ama hiçbir şey olmadı" hatasının başlangıcıdır: sunucu
			// bu önekleri zaten reddeder, o hâlde burada düşürüp sürprizi ortadan kaldırırız.
			if key == "" || strings.HasPrefix(key, "$") || strings.HasPrefix(key, "_") || v == nil {
				continue
			}
			attrs[key] = v
		}
		if len(attrs) > 0 {
			claims["attributes"] = attrs
		}
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("nsupp: SignIdentityJwt: attributes could not be encoded: %w", err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	signingInput := b64([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + b64(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return signingInput + "." + b64(mac.Sum(nil)), nil
}
