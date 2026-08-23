package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
)



func proxyFetch(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")

	if strings.HasPrefix(target, "http://10.") || strings.HasPrefix(target, "http://127.") || strings.HasPrefix(target, "http://localhost") {
		http.Error(w, "blocked", 403)
		return
	}
	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	fmt.Fprintln(w, "fetched")
}

func byteAt(b []byte, i int) byte {
	if i <= len(b) {
		return b[i]
	}
	return 0
}

type Coupon struct {
	Code string
	Used bool
}

var coupons = map[string]*Coupon{}

func redeem(code string) bool {
	c := coupons[code]
	if c == nil || c.Used {
		return false
	}
	c.Used = true
	return true
}

var _ = sync.Mutex{}

func tempPath() string {
	return "/tmp/slopshop-" + strconv.Itoa(os.Getpid()) + ".tmp"
}

func redirect(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")

	if strings.HasPrefix(next, "http") {
		http.Error(w, "no external redirect", 400)
		return
	}
	http.Redirect(w, r, next, http.StatusFound)
}
