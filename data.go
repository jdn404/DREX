package main

import "time"

type Carrier struct {
	Key       string
	Name      string
	Country   string
	IPRanges  []string
	ZeroRated []string
	Ports     []int
	APN       string
}

type Strategy struct {
	Name        string
	Concurrency int
	Timeout     time.Duration
}

type PayloadTemplate struct {
	Name     string
	Template string
}

var Carriers = map[string]Carrier{
	"econet": {
		Key: "econet", Name: "Econet Zimbabwe", Country: "ZW",
		IPRanges:  []string{"41.57.96.0/19", "41.174.64.0/18", "102.65.0.0/16", "196.27.64.0/18"},
		ZeroRated: []string{"econet.co.zw", "ecocash.co.zw", "selfcare.econet.co.zw", "data.econet.co.zw"},
		Ports:     []int{80, 8080, 3128, 8888, 443, 8443, 1080, 3129},
		APN:       "econet",
	},
	"netone": {
		Key: "netone", Name: "NetOne Zimbabwe", Country: "ZW",
		IPRanges:  []string{"41.205.16.0/20", "196.43.160.0/20", "102.130.0.0/16"},
		ZeroRated: []string{"netone.co.zw", "selfcare.netone.co.zw", "www.netone.co.zw"},
		Ports:     []int{80, 8080, 3128, 8888, 443, 3129},
		APN:       "netone",
	},
	"telecel": {
		Key: "telecel", Name: "Telecel Zimbabwe", Country: "ZW",
		IPRanges:  []string{"196.11.240.0/20", "41.77.80.0/20", "102.176.0.0/16"},
		ZeroRated: []string{"telecel.co.zw", "www.telecel.co.zw"},
		Ports:     []int{80, 8080, 3128, 8888, 443},
		APN:       "telecel",
	},
	"mtn": {
		Key: "mtn", Name: "MTN", Country: "ZA",
		IPRanges:  []string{"197.215.0.0/16", "41.21.0.0/16", "102.64.0.0/16", "196.201.0.0/16"},
		ZeroRated: []string{"mtn.com", "myaccount.mtn.com", "ayoba.me", "www.mtn.com"},
		Ports:     []int{80, 8080, 3128, 8888, 443, 8443, 1080},
		APN:       "internet",
	},
	"airtel": {
		Key: "airtel", Name: "Airtel Africa", Country: "NG",
		IPRanges:  []string{"41.223.0.0/16", "102.0.0.0/14", "196.216.0.0/16"},
		ZeroRated: []string{"airtel.com", "airtelzero.com", "www.airtel.com"},
		Ports:     []int{80, 8080, 3128, 8888, 443, 3129},
		APN:       "airtelgprs.com",
	},
	"glo": {
		Key: "glo", Name: "Glo Mobile", Country: "NG",
		IPRanges:  []string{"196.6.0.0/16", "41.211.0.0/16", "102.88.0.0/16"},
		ZeroRated: []string{"gloworld.com", "www.gloworld.com"},
		Ports:     []int{80, 8080, 3128, 8888, 443},
		APN:       "glosecure",
	},
	"zamtel": {
		Key: "zamtel", Name: "Zamtel Zambia", Country: "ZM",
		IPRanges:  []string{"41.72.128.0/18", "196.32.64.0/19", "102.142.0.0/16"},
		ZeroRated: []string{"zamtel.zm", "www.zamtel.zm"},
		Ports:     []int{80, 8080, 3128, 8888, 443},
		APN:       "zamtel",
	},
	"vodacom": {
		Key: "vodacom", Name: "Vodacom", Country: "ZA",
		IPRanges:  []string{"196.15.0.0/16", "41.0.0.0/14", "102.32.0.0/16"},
		ZeroRated: []string{"vodacom.com", "myvodacom.vodacom.co.za", "www.vodacom.com"},
		Ports:     []int{80, 8080, 3128, 8888, 443, 8443},
		APN:       "internet",
	},
	"safaricom": {
		Key: "safaricom", Name: "Safaricom Kenya", Country: "KE",
		IPRanges:  []string{"41.90.0.0/16", "105.163.0.0/16", "196.201.212.0/22"},
		ZeroRated: []string{"safaricom.co.ke", "m-pesa.safaricom.co.ke", "www.safaricom.co.ke"},
		Ports:     []int{80, 8080, 3128, 8888, 443},
		APN:       "safaricom",
	},
	"orange": {
		Key: "orange", Name: "Orange Africa", Country: "SN",
		IPRanges:  []string{"41.82.0.0/16", "197.149.64.0/18", "196.46.0.0/16"},
		ZeroRated: []string{"orange.com", "moncompte.orange.sn", "www.orange.com"},
		Ports:     []int{80, 8080, 3128, 8888, 443},
		APN:       "orange",
	},
	"telkom": {
		Key: "telkom", Name: "Telkom Kenya", Country: "KE",
		IPRanges:  []string{"196.202.96.0/19", "41.215.128.0/18", "102.140.0.0/16"},
		ZeroRated: []string{"telkom.co.ke", "www.telkom.co.ke"},
		Ports:     []int{80, 8080, 3128, 8888, 443},
		APN:       "internet",
	},
	"mtn_gh": {
		Key: "mtn_gh", Name: "MTN Ghana", Country: "GH",
		IPRanges:  []string{"41.189.192.0/18", "196.6.64.0/18", "102.176.64.0/18"},
		ZeroRated: []string{"mtn.com.gh", "mymtn.mtn.com.gh", "www.mtn.com.gh"},
		Ports:     []int{80, 8080, 3128, 8888, 443},
		APN:       "internet",
	},
	"tigo": {
		Key: "tigo", Name: "Tigo Africa", Country: "TZ",
		IPRanges:  []string{"41.188.0.0/16", "196.13.0.0/16"},
		ZeroRated: []string{"tigo.co.tz", "www.tigo.co.tz"},
		Ports:     []int{80, 8080, 3128, 8888, 443},
		APN:       "tigo-internet",
	},
	"halotel": {
		Key: "halotel", Name: "Halotel Tanzania", Country: "TZ",
		IPRanges:  []string{"196.41.64.0/18", "41.86.0.0/16"},
		ZeroRated: []string{"halotel.co.tz", "www.halotel.co.tz"},
		Ports:     []int{80, 8080, 3128, 8888},
		APN:       "internet",
	},
}

var Strategies = map[string]Strategy{
	"turbo":      {Name: "turbo",      Concurrency: 2000, Timeout: 3 * time.Second},
	"aggressive": {Name: "aggressive", Concurrency: 1000, Timeout: 5 * time.Second},
	"balanced":   {Name: "balanced",   Concurrency: 200,  Timeout: 8 * time.Second},
	"stealth":    {Name: "stealth",    Concurrency: 30,   Timeout: 15 * time.Second},
}

func getStrategy(name string) Strategy {
	if s, ok := Strategies[name]; ok {
		return s
	}
	return Strategies["balanced"]
}

var PayloadTemplates = []PayloadTemplate{
	{Name: "direct",    Template: "GET / HTTP/1.1\r\nHost: {h}\r\nConnection: keep-alive\r\n\r\n"},
	{Name: "connect",   Template: "CONNECT {h}:443 HTTP/1.1\r\nHost: {h}\r\nProxy-Connection: Keep-Alive\r\n\r\n"},
	{Name: "ws",        Template: "GET / HTTP/1.1\r\nHost: {h}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"},
	{Name: "xonline",   Template: "GET http://{h}/ HTTP/1.1\r\nHost: {h}\r\nX-Online-Host: {h}\r\nX-Forward-Host: {h}\r\nConnection: Keep-Alive\r\n\r\n"},
	{Name: "xreal",     Template: "GET / HTTP/1.1\r\nHost: {h}\r\nX-Real-IP: 127.0.0.1\r\nX-Forwarded-For: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n"},
	{Name: "via",       Template: "GET http://{h}/ HTTP/1.1\r\nHost: {h}\r\nVia: 1.0 {h}\r\nX-Forwarded-For: 10.0.0.1\r\nConnection: Keep-Alive\r\n\r\n"},
	{Name: "head",      Template: "HEAD / HTTP/1.1\r\nHost: {h}\r\nConnection: keep-alive\r\n\r\n"},
	{Name: "options",   Template: "OPTIONS * HTTP/1.1\r\nHost: {h}\r\nConnection: keep-alive\r\n\r\n"},
	{Name: "post",      Template: "POST / HTTP/1.1\r\nHost: {h}\r\nContent-Length: 0\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: keep-alive\r\n\r\n"},
	{Name: "connect80", Template: "CONNECT {h}:443 HTTP/1.1\r\nHost: {h}:443\r\nUser-Agent: Mozilla/5.0 (Linux; Android 13)\r\nProxy-Connection: keep-alive\r\n\r\n"},
}

var CommonSNI = []string{
	"cloudflare.com", "cdn.cloudflare.net", "cdnjs.cloudflare.com", "cloudflare-dns.com",
	"googleapis.com", "gstatic.com", "googleusercontent.com", "googlevideo.com",
	"fastly.net", "global.fastly.net",
	"akamaiedge.net", "akamaized.net",
	"azureedge.net", "azure.com",
	"amazonaws.com", "cloudfront.net",
	"facebook.com", "fbcdn.net",
	"whatsapp.com", "whatsapp.net",
	"instagram.com", "twitter.com", "twimg.com",
	"tiktok.com", "tiktokcdn.com",
	"youtube.com", "ytimg.com",
	"telegram.org", "discord.com",
	"github.com", "githubusercontent.com",
	"workers.dev", "pages.dev", "netlify.app", "vercel.app",
}
