package truelayer

import (
	"net/url"

	"go.k6.io/k6/js/modules"

	tlsigning "github.com/Truelayer/truelayer-signing/go"
)

func init() {
	modules.Register("k6/x/truelayer", new(Truelayer))
}

type Truelayer struct{}

type Url struct{}

func (*Truelayer) Sign(kid string, pem string, body string) string {
	signature, _ := tlsigning.SignWithPem(kid, []byte(pem)).
		Body([]byte(body)).
		SignBodyOnly()
	return signature
}

func (*Truelayer) ParseUrl(urlToParse string) *url.URL {
	returnValue, _ := url.Parse(urlToParse)
	return returnValue
}
