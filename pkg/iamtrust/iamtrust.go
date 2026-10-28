// Package iamtrust builds the trust policy of an IAM role that people or jobs
// assume with a token from an OIDC issuer registered as an IAM identity
// provider in the account (sts:AssumeRoleWithWebIdentity).
package iamtrust

import (
	"encoding/json"
	"errors"
	"fmt"
)

const (
	assumeWeb         = "sts:AssumeRoleWithWebIdentity"
	tagSession        = "sts:TagSession"
	setSourceIdentity = "sts:SetSourceIdentity"
)

// Policy is a role's trust: the issuer's OIDC provider in the account, pinned
// to the role's own audience. Who may get a token for the audience is the
// issuer's policy; this statement only says the account believes the issuer
// about it. partition is the AWS partition of the provider's ARN; empty means
// "aws".
//
// TagSession is allowed beside AssumeRoleWithWebIdentity because a token
// carrying principal tags fails to assume a role whose trust omits it (AWS
// reports that as a trust error), and adding tags later then needs no trust
// change. SetSourceIdentity lets a session carry the person as its source
// identity through any later role it assumes, which is what CloudTrail
// attributes to them.
//
// The result is compact JSON with sorted keys, stable across calls.
func Policy(partition, accountID, issuerHost, audience string) (string, error) {
	if accountID == "" || issuerHost == "" || audience == "" {
		return "", errors.New("trust policy: accountID, issuerHost and audience are required")
	}

	if partition == "" {
		partition = "aws"
	}

	doc := map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{{
			"Effect": "Allow",
			"Principal": map[string]any{
				"Federated": fmt.Sprintf("arn:%s:iam::%s:oidc-provider/%s", partition, accountID, issuerHost),
			},
			"Action": []string{assumeWeb, tagSession, setSourceIdentity},
			"Condition": map[string]any{
				"StringEquals": map[string]any{
					issuerHost + ":aud": audience,
				},
			},
		}},
	}

	out, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("trust policy: %w", err)
	}

	return string(out), nil
}
