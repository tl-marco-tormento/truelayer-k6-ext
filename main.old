package signing

import (
	"fmt"
	"io/ioutil"

	"go.k6.io/k6/js/modules"

	tlsigning "github.com/Truelayer/truelayer-signing/go"
)

func init() {
	modules.Register("k6/x/truelayer", new(Signing))
}

type Signing struct{}

func (*Signing) Sign(kid string, pem string, body string) string {
	signature, _ := tlsigning.SignWithPem(kid, []byte(pem)).
		Method("post").
		Path("path").
		Body([]byte("body")).
		Sign()
	return signature
}

const (
	Kid = "45fc75cf-5649-4134-84b3-192c2c78e990"
)

func getTestKeys() ([]byte, []byte) {
	privateKeyBytes, _ := ioutil.ReadFile("./testdata/ec512-private.pem")
	publicKeyBytes, _ := ioutil.ReadFile("./testdata/ec512-public.pem")
	return privateKeyBytes, publicKeyBytes
}

func main() {
	privateKeyBytes, publicKeyBytes := getTestKeys()

	body := []byte("{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}")
	idempotencyKey := []byte("idemp-2076717c-9005-4811-a321-9e0787fa0382")
	path := "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping"

	signature, _ := tlsigning.SignWithPem(Kid, privateKeyBytes).
		Method("post").
		Path(path).
		Header("Idempotency-Key", idempotencyKey).
		Body(body).
		Sign()
	fmt.Printf("signature: %s", signature)

	valid, _ := tlsigning.VerifyWithPem(publicKeyBytes).
		Method("POST").
		Path(path).
		RequireHeader("Idempotency-Key").
		Header("X-Whatever-2", []byte("t2345d")).
		Header("Idempotency-Key", idempotencyKey).
		Body(body).
		Verify(signature)

	fmt.Printf("valid: %s", valid)
}
