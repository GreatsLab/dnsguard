// dnsguard - a network-wide DNS sinkhole: blocks ads, trackers and malware
// domains for every device that uses it, caches the rest, and shows you
// what your network is looking up.
package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/GreatsLab/dnsguard/internal/block"
	"github.com/GreatsLab/dnsguard/internal/server"
)

var version = "dev"

//go:embed web
var webFS embed.FS

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func main() {
	var blocks, allows, ups multi
	listen := flag.String("listen", ":53", "DNS listen address (UDP+TCP)")
	httpAddr := flag.String("http", ":8053", "dashboard / API / DoH listen address, empty to disable")
	token := flag.String("token", os.Getenv("DNSGUARD_TOKEN"), "require this bearer token for the API")
	flag.Var(&ups, "upstream", "upstream resolver, repeatable: 1.1.1.1, tls://1.1.1.1#one.one.one.one, https://dns.quad9.net/dns-query")
	flag.Var(&blocks, "block", "blocklist file or URL, repeatable (hosts, domain list or ||adblock^ format)")
	flag.Var(&allows, "allow", "allowlist file, or a domain, repeatable")
	cacheSize := flag.Int("cache", 20000, "max cached answers")
	nx := flag.Bool("nxdomain", false, "answer blocked names with NXDOMAIN instead of 0.0.0.0")
	refresh := flag.Duration("refresh", 24*time.Hour, "re-download URL blocklists this often")
	verbose := flag.Bool("v", false, "log every query")
	showVer := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVer {
		fmt.Println("dnsguard", version)
		return
	}

	lvl := slog.LevelInfo
	if *verbose {
		lvl = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

	if len(ups) == 0 {
		ups = multi{"https://cloudflare-dns.com/dns-query", "https://dns.quad9.net/dns-query"}
	}
	var upstreams []server.Upstream
	for _, u := range ups {
		up, err := server.ParseUpstream(u)
		if err != nil {
			fatal(log, "bad upstream", u, err)
		}
		upstreams = append(upstreams, up)
	}

	list := block.New()
	for _, a := range allows {
		if f, err := os.Open(a); err == nil {
			names := map[string]struct{}{}
			block.Parse(f, names)
			f.Close()
			for n := range names {
				list.Allow(n)
			}
		} else {
			list.Allow(a)
		}
	}
	load := func() {
		all := map[string]struct{}{}
		for _, src := range blocks {
			n, err := loadList(src, all)
			if err != nil {
				log.Warn("blocklist failed, keeping the previous copy", "source", src, "err", err)
				continue
			}
			log.Info("blocklist loaded", "source", src, "domains", n)
		}
		if len(all) > 0 || list.Len() == 0 {
			list.Replace(all)
		}
		log.Info("blocking", "domains", list.Len())
	}
	load()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := server.New(server.Config{Listen: *listen, Upstreams: upstreams, Block: list, CacheSize: *cacheSize,
		Sinkhole: !*nx, MinTTL: 10 * time.Second, Log: log})
	addr, err := srv.Start(ctx)
	if err != nil {
		fatal(log, "can't listen (port 53 needs root or CAP_NET_BIND_SERVICE)", *listen, err)
	}
	log.Info("dns listening", "addr", addr, "upstreams", ups.String())

	if *verbose {
		go func() {
			// cheap live log: poll the ring and print new entries
			var last time.Time
			t := time.NewTicker(time.Second)
			for range t.C {
				es := srv.Stats.Recent(500, func(e server.Entry) bool { return e.Time.After(last) })
				for i := len(es) - 1; i >= 0; i-- {
					e := es[i]
					log.Debug("query", "client", e.Client, "name", e.Name, "type", e.Type, "result", e.Result, "took", e.Took.Round(time.Microsecond))
					last = e.Time
				}
			}
		}()
	}

	if *refresh > 0 && hasURL(blocks) {
		go func() {
			t := time.NewTicker(*refresh)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					load()
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	if *httpAddr != "" {
		static, _ := fs.Sub(webFS, "web")
		hs := &http.Server{Addr: *httpAddr, Handler: srv.HTTP(static, *token), ReadHeaderTimeout: 5 * time.Second}
		go func() {
			log.Info("dashboard", "url", "http://localhost"+*httpAddr)
			if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("http", "err", err)
			}
		}()
		go func() { <-ctx.Done(); hs.Shutdown(context.Background()) }()
	}

	<-ctx.Done()
	log.Info("bye")
}

func hasURL(srcs []string) bool {
	for _, s := range srcs {
		if strings.HasPrefix(s, "http") {
			return true
		}
	}
	return false
}

func loadList(src string, dst map[string]struct{}) (int, error) {
	var r io.ReadCloser
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		c := &http.Client{Timeout: 60 * time.Second}
		resp, err := c.Get(src)
		if err != nil {
			return 0, err
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return 0, fmt.Errorf("%s", resp.Status)
		}
		r = resp.Body
	} else {
		f, err := os.Open(src)
		if err != nil {
			return 0, err
		}
		r = f
	}
	defer r.Close()
	return block.Parse(r, dst)
}

func fatal(log *slog.Logger, msg string, what any, err error) {
	log.Error(msg, "what", what, "err", err)
	os.Exit(1)
}
