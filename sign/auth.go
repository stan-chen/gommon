package sign

import (
	"net/http"
)

type Authenticator interface {
	Auth(r *http.Request) error
}

type Credential interface {
	AccessKeyID() string
	AccessKeyByte() []byte
}
