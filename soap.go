package hikrec

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/xml"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

type SOAP struct {
	Body     string
	XMLNs    []string
	User     string
	Password string
	TokenAge time.Duration
	Action   string
	NoDebug  bool
}

func (soap SOAP) SendRequest(xaddr string, to string) (*Envelope, error) {
	request := soap.createRequest(to)

	urlXAddr, err := url.Parse(xaddr)
	if err != nil {
		return nil, err
	}

	if soap.User != "" {
		urlXAddr.User = url.UserPassword(soap.User, soap.Password)
	}

	buffer := bytes.NewBuffer([]byte(request))
	req, err := http.NewRequest("POST", urlXAddr.String(), buffer)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/soap+xml")
	req.Header.Set("Charset", "utf-8")

	var httpDigestClient = NewTransport(soap.User, soap.Password)
	resp, err := httpDigestClient.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var envelope Envelope
	if err := xml.Unmarshal(responseBody, &envelope); err != nil {
		return nil, err
	}

	return &envelope, nil
}

func (soap SOAP) createRequest(to string) string {
	request := `<?xml version="1.0" encoding="UTF-8"?>`
	request += `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"`

	for _, namespace := range soap.XMLNs {
		request += " " + namespace
	}
	request += ">"

	if soap.Action != "" || soap.User != "" {
		request += "<s:Header>"

		if soap.Action != "" {
			request += `<Action mustUnderstand="1"
							   xmlns="http://www.w3.org/2005/08/addressing">` + soap.Action + `</Action>`
		}

		if soap.User != "" {
			request += soap.createUserToken()
		}

		if to != "" {
			request += `<wsa:To>` + to + `</wsa:To>`
		}

		request += "</s:Header>"
	}

	request += "<s:Body>" + soap.Body + "</s:Body>"

	request += "</s:Envelope>"

	request = regexp.MustCompile(`\>\s+\<`).ReplaceAllString(request, "><")
	request = regexp.MustCompile(`\s+`).ReplaceAllString(request, " ")

	return request
}

func (soap SOAP) createUserToken() string {
	now := time.Now()
	nonce := strconv.FormatInt(now.UnixNano(), 10)
	nonce64 := base64.StdEncoding.EncodeToString(([]byte)(nonce))
	timestamp := now.Add(soap.TokenAge).UTC().Format(time.RFC3339)
	token := string(nonce) + timestamp + soap.Password

	sha := sha1.New()
	sha.Write([]byte(token))
	shaToken := sha.Sum(nil)
	shaDigest64 := base64.StdEncoding.EncodeToString(shaToken)

	return `<Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  		<UsernameToken>
    		<Username>` + soap.User + `</Username>
    		<Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">` + shaDigest64 + `</Password>
    		<Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">` + nonce64 + `</Nonce>
    		<Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">` + timestamp + `</Created>
		</UsernameToken>
	</Security>`
}
