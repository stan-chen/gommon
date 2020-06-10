package sign

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

type credential struct {
	id  string
	key []byte
}

func (c *credential) AccessKeyID() string {
	return c.id
}

func (c *credential) AccessKeyByte() []byte {
	return c.key
}

func getCreds(key string) Credential {
	if key == "aaa" {
		return &credential{
			id:  "aaa",
			key: []byte("bbb"),
		}
	}
	return nil
}

func TestSimpleAuthenticator_Auth_NoAccessID(t *testing.T) {
	a := SimpleAuthenticator{getCreds}

	u, _ := url.Parse("https://10.10.22.25/absd askljq asdasd/")
	query := u.Query()
	query.Set(timestampQueryKey, formatTime(time.Now()))
	query.Set(signatureQueryKey, hex.EncodeToString(hmacSHA256([]byte(""), []byte(""))))
	u.RawQuery = query.Encode()

	r := httptest.NewRequest("GET", u.String(), nil)
	r.Header.Set("X-Content-Sha256", hex.EncodeToString(hmacSHA256([]byte(""), []byte(""))))

	err := a.Auth(r)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error access_id")
}
