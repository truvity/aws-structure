package registry

// ISO27001PasswordPolicy is the account password policy an ISO 27001 audit
// (and a compliance scanner that tests it, such as Vanta's "minimum length"
// and "no password reuse" tests) expects: at least 14 characters, rotated
// every 90 days, none of the last 24 reused, and every character class
// required.
//
// It returns a new value each call, so a caller may adjust its copy.
func ISO27001PasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinimumLength:    14,
		MaxAgeDays:       90,
		ReusePrevention:  24,
		RequireSymbols:   true,
		RequireNumbers:   true,
		RequireUppercase: true,
		RequireLowercase: true,
	}
}
