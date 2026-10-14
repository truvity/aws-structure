// Command awsorgctl is the command line over aws-structure: it validates a
// registry, runs the preflight over a preview's event log, reads the live
// organization back for drift, writes the access-roles map and renders the
// Identity Center aws.ini. Nothing it does writes to AWS.
//
//	awsorgctl validate     -registry r.yaml
//	awsorgctl preflight    -registry r.yaml -events preview.jsonl [-break-glass-set ARN -break-glass-principal ID]
//	awsorgctl drift        -registry r.yaml -profile mgmt -sso-region R [-fail]
//	awsorgctl access-roles -registry r.yaml -profile mgmt [-role R] [-partition P] [-out f.yaml] [-header TEXT]
//	awsorgctl aws-ini      -registry r.yaml -start-url URL -sso-region R -region R [-default P] [-out ~/.aws/config]
//
// Exit codes: 0 clean, 1 findings (a refusal, drift with -fail), 2 usage or
// an error.
package main

import (
	"os"
)

// Version is set at release (-X main.Version).
var Version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
