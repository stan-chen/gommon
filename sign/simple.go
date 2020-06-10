package sign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	timeFormat         = "20060102T150405Z"
	signatureQueryKey  = "signature"
	credentialQueryKey = "credential"
	timestampQueryKey  = "date"
	expiresQueryKey    = "expires"
	bodyHashHeaderKey  = "X-Content-Sha256"
)

type CredentialCb func(string) Credential

type SimpleAuthenticator struct {
	GetSecret CredentialCb
}

type simpleSignContext struct {
	Request    *http.Request
	Query      url.Values
	Time       time.Time
	ExpireTime time.Duration

	credential Credential

	bodyDigest   string
	stringToSign string

	signature  string
	rSignature string
}

func (ctx *simpleSignContext) popQuery(key string) string {
	t := ctx.Query.Get(key)
	ctx.Query.Del(key)
	return t
}

func (ctx *simpleSignContext) handlePresignRemoval() error {
	var err error
	timeValue := ctx.popQuery(timestampQueryKey)
	if ctx.Time, err = time.Parse(timeFormat, timeValue); err != nil {
		return err
	}

	expireTimeValue := ctx.popQuery(expiresQueryKey)
	if expireTimeValue != "" {
		ctx.ExpireTime, err = time.ParseDuration(expireTimeValue)
		if err != nil {
			return fmt.Errorf("cannot format %s to duration", expiresQueryKey)
		}
		if ctx.Time.Add(ctx.ExpireTime).Before(time.Now()) {
			return fmt.Errorf("time expired")
		}
	}

	return nil
}

func (ctx *simpleSignContext) buildBodyDigest() error {
	hash := ctx.Request.Header.Get(bodyHashHeaderKey)
	if len(hash) != 64 {
		return fmt.Errorf("cannot find header %s", bodyHashHeaderKey)
	}
	ctx.bodyDigest = hash
	return nil
}

func (ctx *simpleSignContext) rebuild() {
	uri := getURIPath(ctx.Request.URL)
	rawQuery := strings.Replace(ctx.Query.Encode(), "+", "%20", -1)

	ctx.stringToSign = strings.Join([]string{
		ctx.Request.Method,
		uri,
		rawQuery,
		formatTime(ctx.Time),
		ctx.credential.AccessKeyID(),
		ctx.bodyDigest,
	}, "\n")

	signature := hmacSHA256(ctx.credential.AccessKeyByte(), []byte(ctx.stringToSign))
	ctx.signature = hex.EncodeToString(signature)
}

func (a *SimpleAuthenticator) Auth(r *http.Request) error {
	var err error
	ctx := &simpleSignContext{
		Request: r,
		Query:   r.URL.Query(),
	}

	for key := range ctx.Query {
		sort.Strings(ctx.Query[key])
	}

	if err = ctx.handlePresignRemoval(); err != nil {
		return err
	}

	accessKeyID := ctx.popQuery(credentialQueryKey)
	ctx.rSignature = ctx.popQuery(signatureQueryKey)

	if len(ctx.rSignature) != 64 {
		return fmt.Errorf("signature invalid length")
	}

	ctx.credential = a.GetSecret(accessKeyID)
	if ctx.credential == nil {
		return fmt.Errorf("error access_id")
	}

	if err = ctx.buildBodyDigest(); err != nil {
		return err
	}

	ctx.rebuild()

	if ctx.signature != ctx.rSignature {
		return fmt.Errorf("signature not match")
	}

	return nil
}

func getURIPath(u *url.URL) string {
	var uri string
	if len(u.Opaque) > 0 {
		uri = "/" + strings.Join(strings.Split(u.Opaque, "/")[3:], "/")
	} else {
		uri = u.EscapedPath()
	}
	if len(uri) == 0 {
		uri = "/"
	}
	return uri
}

func hmacSHA256(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

func formatTime(dt time.Time) string {
	return dt.UTC().Format(timeFormat)
}
