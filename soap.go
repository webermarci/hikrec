package hikrec

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/xml"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type SOAP struct {
	Body     string
	User     string
	Password string
	Action   string
}

func (soap SOAP) SendRequest(xaddr string, to string) (*Envelope, error) {
	request := soap.createRequest(to)

	urlXAddr, err := url.Parse(xaddr)
	if err != nil {
		return nil, err
	}

	urlXAddr.User = url.UserPassword(soap.User, soap.Password)

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
	var sb strings.Builder

	sb.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
	sb.WriteString("<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">")

	sb.WriteString("<s:Header>")

	sb.WriteString("<Action mustUnderstand=\"1\" xmlns=\"http://www.w3.org/2005/08/addressing\">" + soap.Action + "</Action>")

	sb.WriteString(soap.createUserToken())

	sb.WriteString("<wsa:To>" + to + "</wsa:To>")

	sb.WriteString("</s:Header>")

	sb.WriteString("<s:Body>" + soap.Body + "</s:Body>")
	sb.WriteString("</s:Envelope>")

	return sb.String()
}

func (soap SOAP) createUserToken() string {
	now := time.Now()
	nonce := strconv.FormatInt(now.UnixNano(), 10)
	nonce64 := base64.StdEncoding.EncodeToString(([]byte)(nonce))
	timestamp := now.UTC().Format(time.RFC3339)
	token := string(nonce) + timestamp + soap.Password

	sha := sha1.New()
	sha.Write([]byte(token))
	shaToken := sha.Sum(nil)
	shaDigest64 := base64.StdEncoding.EncodeToString(shaToken)

	return "<Security s:mustUnderstand=\"1\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><UsernameToken><Username>" + soap.User + "</Username><Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">" + shaDigest64 + "</Password><Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">" + nonce64 + "</Nonce><Created xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">" + timestamp + "</Created></UsernameToken></Security>"
}
