package truelayer

import (
	"net/url"
	"time"

	"go.k6.io/k6/js/modules"

	tlsigning "github.com/Truelayer/truelayer-signing/go"
)

func init() {
	modules.Register("k6/x/truelayer", New())
}

type (
	// RootModule is the global module instance that will create Truelayer
	// instances for each VU.
	RootModule struct{}

	// TruelayerModule represents an instance of the JS module.
	TruelayerModuleInstance struct {
		// Truelayer is the exported module instance.
		*Truelayer
	}
)

// Ensure the interfaces are implemented correctly.
var (
	_ modules.Instance = &TruelayerModuleInstance{}
	_ modules.Module   = &RootModule{}
)

// New returns a pointer to a new RootModule instance.
func New() *RootModule {
	return &RootModule{}
}

// NewModuleInstance implements the modules.Module interface and returns
// a new instance for each VU.
func (*RootModule) NewModuleInstance(vu modules.VU) modules.Instance {
	return &TruelayerModuleInstance{Truelayer: &Truelayer{}}
}

// Truelayer is the exported module instance.
type Truelayer struct{}

func (*Truelayer) Sign(kid string, pem string, path string, method string, headers map[string][]byte, body string) string {
	signature, _ := tlsigning.SignWithPem(kid, []byte(pem)).
		Path(path).
		Method(method).
		Headers(headers).
		Body([]byte(body)).
		Sign()
	return signature
}

func (*Truelayer) ParseUrl(urlToParse string) *url.URL {
	returnValue, _ := url.Parse(urlToParse)
	return returnValue
}

func (*Truelayer) GetTimeNano() int64 {
	return time.Now().UnixNano()
}

// Exports implements the modules.Instance interface and returns the exports
// of the JS module.
func (t *TruelayerModuleInstance) Exports() modules.Exports {
	return modules.Exports{Default: t.Truelayer}
}
