// Copyright 2013 M-Lab
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The digest package provides an implementation of http.RoundTripper that takes
// care of HTTP Digest Authentication (http://www.ietf.org/rfc/rfc2617.txt).
// This only implements the MD5 and "auth" portions of the RFC, but that covers
// the majority of avalible server side implementations including apache web
// server.
package hikrec

import (
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"
)

var (
	ErrNilTransport      = errors.New("transport is nil")
	ErrBadChallenge      = errors.New("challenge is bad")
	ErrAlgNotImplemented = errors.New("alg not implemented")
)

type Transport struct {
	Username  string
	Password  string
	Transport http.RoundTripper
}

func NewTransport(username, password string) *Transport {
	t := &Transport{
		Username: username,
		Password: password,
	}
	t.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return t
}

type challenge struct {
	Realm     string
	Domain    string
	Nonce     string
	Opaque    string
	Stale     string
	Algorithm string
	Qop       string
}

func parseChallenge(input string) (*challenge, error) {
	const ws = " \n\r\t"
	const qs = `"`
	s := strings.Trim(input, ws)
	if !strings.HasPrefix(s, "Digest ") {
		return nil, ErrBadChallenge
	}
	s = strings.Trim(s[7:], ws)
	sl := strings.Split(s, ", ")
	c := &challenge{
		Algorithm: "MD5",
	}
	var r []string
	for i := range sl {
		r = strings.SplitN(sl[i], "=", 2)
		switch r[0] {
		case "realm":
			c.Realm = strings.Trim(r[1], qs)
		case "domain":
			c.Domain = strings.Trim(r[1], qs)
		case "nonce":
			c.Nonce = strings.Trim(r[1], qs)
		case "opaque":
			c.Opaque = strings.Trim(r[1], qs)
		case "stale":
			c.Stale = strings.Trim(r[1], qs)
		case "algorithm":
			c.Algorithm = strings.Trim(r[1], qs)
		case "qop":
			c.Qop = strings.Trim(r[1], qs)
		default:
			return nil, ErrBadChallenge
		}
	}
	return c, nil
}

type credentials struct {
	Username   string
	Realm      string
	Nonce      string
	DigestURI  string
	Algorithm  string
	Cnonce     string
	Opaque     string
	MessageQop string
	NonceCount int
	method     string
	password   string
}

func h(data string) string {
	hf := md5.New()
	io.WriteString(hf, data)
	return fmt.Sprintf("%x", hf.Sum(nil))
}

func kd(secret, data string) string {
	return h(fmt.Sprintf("%s:%s", secret, data))
}

func (c *credentials) ha1() string {
	return h(fmt.Sprintf("%s:%s:%s", c.Username, c.Realm, c.password))
}

func (c *credentials) ha2() string {
	return h(fmt.Sprintf("%s:%s", c.method, c.DigestURI))
}

func (c *credentials) resp(cnonce string) (string, error) {
	c.NonceCount++
	if c.MessageQop == "auth" {
		if cnonce != "" {
			c.Cnonce = cnonce
		} else {
			b := make([]byte, 8)
			io.ReadFull(rand.Reader, b)
			c.Cnonce = fmt.Sprintf("%x", b)[:16]
		}
		return kd(c.ha1(), fmt.Sprintf("%s:%08x:%s:%s:%s",
			c.Nonce, c.NonceCount, c.Cnonce, c.MessageQop, c.ha2())), nil
	} else if c.MessageQop == "" {
		return kd(c.ha1(), fmt.Sprintf("%s:%s", c.Nonce, c.ha2())), nil
	}
	return "", ErrAlgNotImplemented
}

func (c *credentials) authorize() (string, error) {
	if c.Algorithm != "MD5" {
		return "", ErrAlgNotImplemented
	}
	if c.MessageQop != "auth" && c.MessageQop != "" {
		return "", ErrAlgNotImplemented
	}
	resp, err := c.resp("")
	if err != nil {
		return "", ErrAlgNotImplemented
	}
	sl := []string{fmt.Sprintf(`username="%s"`, c.Username)}
	sl = append(sl, fmt.Sprintf(`realm="%s"`, c.Realm))
	sl = append(sl, fmt.Sprintf(`nonce="%s"`, c.Nonce))
	sl = append(sl, fmt.Sprintf(`uri="%s"`, c.DigestURI))
	sl = append(sl, fmt.Sprintf(`response="%s"`, resp))
	if c.Algorithm != "" {
		sl = append(sl, fmt.Sprintf(`algorithm="%s"`, c.Algorithm))
	}
	if c.Opaque != "" {
		sl = append(sl, fmt.Sprintf(`opaque="%s"`, c.Opaque))
	}
	if c.MessageQop != "" {
		sl = append(sl, fmt.Sprintf("qop=%s", c.MessageQop))
		sl = append(sl, fmt.Sprintf("nc=%08x", c.NonceCount))
		sl = append(sl, fmt.Sprintf(`cnonce="%s"`, c.Cnonce))
	}
	return fmt.Sprintf("Digest %s", strings.Join(sl, ", ")), nil
}

func (t *Transport) newCredentials(req *http.Request, c *challenge) *credentials {
	return &credentials{
		Username:   t.Username,
		Realm:      c.Realm,
		Nonce:      c.Nonce,
		DigestURI:  req.URL.RequestURI(),
		Algorithm:  c.Algorithm,
		Opaque:     c.Opaque,
		MessageQop: c.Qop,
		NonceCount: 0,
		method:     req.Method,
		password:   t.Password,
	}
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Transport == nil {
		return nil, ErrNilTransport
	}

	req2 := new(http.Request)
	*req2 = *req
	req2.Header = make(http.Header)
	for k, s := range req.Header {
		req2.Header[k] = s
	}

	resp, err := t.Transport.RoundTrip(req)
	if err != nil || resp.StatusCode != 401 {
		return resp, err
	}
	chal := resp.Header.Get("WWW-Authenticate")
	c, err := parseChallenge(chal)
	if err != nil {
		_, errR := ioutil.ReadAll(resp.Body)
		if errR == nil {
			return resp, err
		}
		return resp, errR
	}

	cr := t.newCredentials(req2, c)
	auth, err := cr.authorize()
	if err != nil {
		return resp, err
	}

	resp.Body.Close()

	req2.Header.Set("Authorization", auth)
	return t.Transport.RoundTrip(req2)
}
