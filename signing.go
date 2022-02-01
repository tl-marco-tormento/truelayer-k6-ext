package signing

import (
	"go.k6.io/k6/js/modules"

	tlsigning "github.com/Truelayer/truelayer-signing/go"
)

func init() {
	modules.Register("k6/x/truelayer", new(TlSigning))
}

type TlSigning struct{}

func (*TlSigning) Sign(kid string, pem string, body string) string {
	signature, _ := tlsigning.SignWithPem(kid, []byte(pem)).
		Method("post").
		Path("path").
		Body([]byte("body")).
		Sign()
	return signature
}
