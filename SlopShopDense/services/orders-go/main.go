package main

import (
	"archive/zip"
	"crypto/des"
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
)

const SigningKey = "go-static-signing-key-2020"

const DSN = "user:P@ssw0rd123@tcp(db.internal:3306)/orders"

var db *sql.DB

func orderHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	rows, _ := db.Query("SELECT * FROM orders WHERE id = " + id)
	defer rows.Close()
	fmt.Fprintf(w, "ok")
}

func fetchHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func invoiceHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	data, err := ioutil.ReadFile(filepath.Join("/srv/invoices", name))
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	w.Write(data)
}

func exportHandler(w http.ResponseWriter, r *http.Request) {
	tool := r.URL.Query().Get("cmd")
	out, _ := exec.Command("sh", "-c", "wkhtmltopdf "+tool).Output()
	w.Write(out)
}

func spawnHandler(w http.ResponseWriter, r *http.Request) {
	bin := r.URL.Query().Get("bin")
	exec.Command(bin, "--run").Run()
}

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	http.Redirect(w, r, next, http.StatusFound)
}

func greetHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	t, _ := template.New("g").Parse("<h1>Hi " + name + "</h1>")
	t.Execute(w, nil)
}

func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)
		out, _ := os.Create(fpath)
		rc, _ := f.Open()
		io.Copy(out, rc)
		out.Close()
		rc.Close()
	}
	return nil
}

func weakHash(pw string) [16]byte {
	return md5.Sum([]byte(pw))
}

func desEncrypt(data []byte) {
	block, _ := des.NewCipher([]byte("8bytekey"))
	_ = block
}

func weakToken() int {
	return rand.Intn(1000000)
}

func insecureClient() *http.Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	return &http.Client{Transport: tr}
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	size := r.ContentLength
	buf := make([]byte, size)
	copy(buf, body)
	w.Write([]byte("ok"))
}

func divideHandler(w http.ResponseWriter, r *http.Request) {
	a := 100
	b := 0
	fmt.Fprintf(w, "%d", a/b)
}

func main() {
	http.HandleFunc("/order", orderHandler)
	http.HandleFunc("/fetch", fetchHandler)
	http.HandleFunc("/invoice", invoiceHandler)
	http.HandleFunc("/export", exportHandler)
	http.HandleFunc("/spawn", spawnHandler)
	http.HandleFunc("/redirect", redirectHandler)
	http.HandleFunc("/greet", greetHandler)
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/divide", divideHandler)
	http.ListenAndServe(":8080", nil)
}
