package backend

import "fmt"

// URLOption customizes SecretsProviderURL.
type URLOption func(*urlConfig)

type urlConfig struct {
	contextPurpose string
}

// WithContextPurpose appends "&context_purpose=<purpose>" to the URL, so
// Pulumi passes the KMS encryption context {purpose: <purpose>} on every
// Encrypt and Decrypt. Use it when the key policy allows Pulumi only with
// that context (a condition on kms:EncryptionContext:purpose). An empty
// purpose adds nothing.
func WithContextPurpose(purpose string) URLOption {
	return func(c *urlConfig) { c.contextPurpose = purpose }
}

// SecretsProviderURL returns the Pulumi secrets provider URL of a state
// bucket's key, by its alias (KMSAlias) in region, reached with profile:
// "awskms://alias/pulumi-state?awssdk=v2&region=<region>&profile=<profile>",
// plus "&context_purpose=<purpose>" with WithContextPurpose.
func SecretsProviderURL(region, profile string, opts ...URLOption) string {
	var c urlConfig
	for _, o := range opts {
		o(&c)
	}

	u := fmt.Sprintf("awskms://%s?awssdk=v2&region=%s&profile=%s", KMSAlias(), region, profile)
	if c.contextPurpose != "" {
		u += "&context_purpose=" + c.contextPurpose
	}

	return u
}
