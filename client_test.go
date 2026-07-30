package nsupp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

type call struct {
	method, url string
	headers     map[string]string
	body        string
}

func mockTransport(calls *[]call, queue []struct {
	status int
	body   string
}) Transport {
	i := 0
	return func(method, u string, headers map[string]string, body []byte) (int, []byte, error) {
		*calls = append(*calls, call{method: method, url: u, headers: headers, body: string(body)})
		var nxt struct {
			status int
			body   string
		}
		if i < len(queue) {
			nxt = queue[i]
			i++
		} else {
			nxt = struct {
				status int
				body   string
			}{200, `{"error":false,"data":{}}`}
		}
		return nxt.status, []byte(nxt.body), nil
	}
}

func TestAuthAndEnvelope(t *testing.T) {
	var calls []call
	c, err := New(Config{Identifier: "nsupp_pk_abc", Secret: "s3cr3t", Transport: mockTransport(&calls, []struct {
		status int
		body   string
	}{{200, `{"error":false,"data":{"name":"Acme"}}`}})})
	if err != nil {
		t.Fatal(err)
	}
	data, err := c.Request("GET", "/v1/website/pk1", nil)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := data.(map[string]any)
	if m["name"] != "Acme" {
		t.Fatalf("data açılmadı: %v", data)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("nsupp_pk_abc:s3cr3t"))
	if calls[0].headers["Authorization"] != want {
		t.Fatalf("auth başlığı yanlış: %s", calls[0].headers["Authorization"])
	}
	if calls[0].headers["X-Cof-Tier"] != "plugin" {
		t.Fatal("X-Cof-Tier plugin değil")
	}
	if calls[0].url != "https://api.nsupp.com/cof/v1/website/pk1" {
		t.Fatalf("url yanlış: %s", calls[0].url)
	}
}

func TestErrorEnvelope(t *testing.T) {
	var calls []call
	c, _ := New(Config{Identifier: "i", Secret: "s", Transport: mockTransport(&calls, []struct {
		status int
		body   string
	}{{403, `{"error":true,"reason":"scope denied","code":"scope_denied"}`}})})
	_, err := c.Request("GET", "/v1/website/pk1/people/profiles", nil)
	var ne *Error
	if !errors.As(err, &ne) {
		t.Fatalf("*Error beklendi: %v", err)
	}
	if ne.Message != "scope denied" || ne.Code != "scope_denied" || ne.Status != 403 {
		t.Fatalf("Error alanları yanlış: %+v", ne)
	}
}

func TestQueryBodyAndWebsiteScope(t *testing.T) {
	var calls []call
	c, _ := New(Config{Identifier: "i", Secret: "s", WebsiteID: "pk9", Transport: mockTransport(&calls, []struct {
		status int
		body   string
	}{{200, `{"error":false,"data":[]}`}, {200, `{"error":false,"data":{"fingerprint":"m1"}}`}, {200, `{"error":false,"data":{"delivered":true}}`}})})
	w, err := c.Website()
	if err != nil {
		t.Fatal(err)
	}
	if w.WebsiteID != "pk9" {
		t.Fatal("websiteID pk9 değil")
	}
	_, _ = w.ListConversations(map[string]string{"page": "1", "empty": ""})
	if calls[0].url != "https://api.nsupp.com/cof/v1/website/pk9/conversations?page=1" {
		t.Fatalf("query url yanlış: %s", calls[0].url)
	}
	_, _ = w.SendMessage("s1", "merhaba")
	var sent map[string]any
	_ = json.Unmarshal([]byte(calls[1].body), &sent)
	if sent["content"] != "merhaba" || calls[1].headers["Content-Type"] != "application/json" {
		t.Fatalf("body/header yanlış: %s", calls[1].body)
	}
	_, _ = w.EmailReply("s1", "yanıt")
	if calls[2].url != "https://api.nsupp.com/cof/v1/website/pk9/conversation/s1/email-reply" {
		t.Fatalf("email-reply url yanlış: %s", calls[2].url)
	}
}

func TestFaz56SupportHelpers(t *testing.T) {
	var calls []call
	c, _ := New(Config{Identifier: "i", Secret: "s", WebsiteID: "pk9", Transport: mockTransport(&calls, nil)})
	w, _ := c.Website()
	base := "https://api.nsupp.com/cof/v1/website/pk9"
	_, _ = w.AddInternalNote("s1", "iç not")
	if calls[0].method != "POST" || calls[0].url != base+"/conversation/s1/note" {
		t.Fatalf("note yol yanlış: %s %s", calls[0].method, calls[0].url)
	}
	_, _ = w.GetContact("s1")
	if calls[1].url != base+"/conversation/s1/contact" {
		t.Fatalf("contact yol yanlış: %s", calls[1].url)
	}
	_, _ = w.RemoveParticipant("s1", "lee@acme.com")
	if calls[2].method != "DELETE" || calls[2].url != base+"/conversation/s1/participants/lee@acme.com" {
		t.Fatalf("removeParticipant yol yanlış: %s %s", calls[2].method, calls[2].url)
	}
	_, _ = w.CreateCannedReply(map[string]any{"shortcut": "iade", "body": "3-5"})
	if calls[3].method != "POST" || calls[3].url != base+"/canned-replies" {
		t.Fatalf("canned yol yanlış: %s %s", calls[3].method, calls[3].url)
	}
	_, _ = w.ListOrderNotes("trendyol", "TY-4471")
	if calls[4].url != base+"/orders/notes?connector=trendyol&order=TY-4471" {
		t.Fatalf("order-notes query yanlış: %s", calls[4].url)
	}
	_, _ = w.DeleteOrderNote("on1")
	if calls[5].method != "DELETE" || calls[5].url != base+"/orders/notes/on1" {
		t.Fatalf("deleteOrderNote yol yanlış: %s %s", calls[5].method, calls[5].url)
	}
}

func TestHeadAndOverrides(t *testing.T) {
	var calls []call
	c, _ := New(Config{Identifier: "i", Secret: "s", Tier: "website", BaseURL: "http://localhost:8788/cof/", Transport: mockTransport(&calls, []struct {
		status int
		body   string
	}{{200, ``}, {404, ``}})})
	if _, err := c.Request("HEAD", "/v1/website/pk1/conversation/s1", nil); err != nil {
		t.Fatalf("HEAD 2xx hata verdi: %v", err)
	}
	if calls[0].headers["X-Cof-Tier"] != "website" {
		t.Fatal("tier override çalışmadı")
	}
	if calls[0].url != "http://localhost:8788/cof/v1/website/pk1/conversation/s1" {
		t.Fatalf("baseURL trim yanlış: %s", calls[0].url)
	}
	_, err := c.Request("HEAD", "/v1/website/pk1/conversation/nope", nil)
	var ne *Error
	if !errors.As(err, &ne) || ne.Status != 404 {
		t.Fatalf("HEAD 404 *Error(404) beklendi: %v", err)
	}
}

func TestRequiredArgs(t *testing.T) {
	if _, err := New(Config{Secret: "s"}); err == nil {
		t.Fatal("Identifier zorunlu olmalı")
	}
	c, _ := New(Config{Identifier: "i", Secret: "s", Transport: func(string, string, map[string]string, []byte) (int, []byte, error) { return 200, []byte("{}"), nil }})
	if _, err := c.Website(); err == nil {
		t.Fatal("websiteID olmadan hata olmalı")
	}
}

func TestVerifyWebhook(t *testing.T) {
	secret := "cof_whsec_test"
	payload := `{"id":"evt_1","event":"message:received"}`
	ts := "1784361825398"
	var tsNum int64 = 1784361825398
	// Bağımsız oracle: sunucunun imzaladığı gibi HMAC-SHA256(`${ts};${body}`).
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + ";" + payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	if !VerifyWebhook(payload, sig, ts, secret, 0, tsNum+1000) {
		t.Fatal("geçerli imza + taze ts → true olmalı")
	}
	if VerifyWebhook(payload+" ", sig, ts, secret, 0, tsNum+1000) {
		t.Fatal("kurcalanmış gövde → false olmalı")
	}
	if VerifyWebhook(payload, sig, ts, secret, 0, tsNum+6*60*1000) {
		t.Fatal("bayat ts (replay) → false olmalı")
	}
	if VerifyWebhook(payload, sig, "nope", secret, 0, tsNum) {
		t.Fatal("sayısal olmayan ts → false olmalı")
	}
}

func TestSignIdentity(t *testing.T) {
	// ALTIN VEKTÖRLER — sunucunun kendi çıktısı; diller arası sözleşme. Beklenen imzalar SABİT
	// yazılır (yeniden hesaplanmaz): oracle'ı burada kurmak, kanonik biçim kayarsa testi de
	// birlikte kaydırırdı.
	secret := "cof_idv_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	vectors := []struct{ raw, canon, sig string }{
		{"  Jane@Acme.COM ", "jane@acme.com", "323dac99d5f34749a31d2d259656694d5e9d229ee2e082bebeac179d01227ba7"},
		{"jane@acme.com", "jane@acme.com", "323dac99d5f34749a31d2d259656694d5e9d229ee2e082bebeac179d01227ba7"},
		// ASCII-dışı harfler OLDUĞU GİBİ kalır (İ ve Ö korunur) — bilinçli, dokümante sınır.
		{"İSTANBUL@X.com", "İstanbul@x.com", "84b516b5e7726e82f5ac7ac39503c02536a3ef0d9aafa40c97d6268c2d83ee14"},
		{"Ömer@Example.COM", "Ömer@example.com", "a7270723fac1793d032910ea1231939a8f9d5c3cab49049b243e875a671f0297"},
		{"\t\r\n\v\f a@b.co \t\n", "a@b.co", "7c41ce285323036c431de959bc0ef1388be7a5e9767add221e73496d3c8297a2"},
	}
	for _, v := range vectors {
		if got := CanonicalIdentityEmail(v.raw); got != v.canon {
			t.Fatalf("kanonik biçim yanlış: %q → %q, beklenen %q", v.raw, got, v.canon)
		}
		got, err := SignIdentity(v.raw, secret)
		if err != nil {
			t.Fatalf("SignIdentity(%q) beklenmedik hata: %v", v.raw, err)
		}
		if got != v.sig {
			t.Fatalf("imza yanlış: %q → %s, beklenen %s", v.raw, got, v.sig)
		}
	}
}
