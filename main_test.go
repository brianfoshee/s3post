package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestEncodingPolicy(t *testing.T) {
	b64 := base64.StdEncoding
	policy := strings.Replace(policy, "\n", "\r\n", -1)

	p := b64.EncodeToString([]byte(policy))

	decPolicy, _ := b64.DecodeString(encPolicy)
	if string(decPolicy) != policy {
		t.Errorf("decoded policy is not equal to expected policy\n%s\n\n%s\n", decPolicy, policy)
	}

	if p != encPolicy {
		t.Errorf("policy is not equal to expected encoded policy\n%q\n\n%q\n", p, encPolicy)
	}
}

func TestEncodedSignature(t *testing.T) {
	s256 := sha256.New

	dk := hmac.New(s256, []byte("AWS4"+awsSecret))
	dk.Write([]byte("20151229"))

	drk := hmac.New(s256, dk.Sum(nil))
	drk.Write([]byte("us-east-1"))

	drsk := hmac.New(s256, drk.Sum(nil))
	drsk.Write([]byte("s3"))

	signingKey := hmac.New(s256, drsk.Sum(nil))
	signingKey.Write([]byte("aws4_request"))

	signature := hmac.New(s256, signingKey.Sum(nil))
	signature.Write([]byte(encPolicy))

	// encode signature using hex encoding
	encsig := make([]byte, hex.EncodedLen(signature.Size()))
	hex.Encode(encsig, signature.Sum(nil))

	if string(encsig) != encSignature {
		t.Errorf("signed signature is not equal to expected\n%q\n%q\n", encsig, encSignature)
	}
}

const (
	encSignature = "8afdbf4008c03f22c2cd3cdb72e4afbb1f6a588f3255ac628749a66d7f09699e"
	awsKey       = "AKIAIOSFODNN7EXAMPLE"
	awsSecret    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	policy       = `{ "expiration": "2015-12-30T12:00:00.000Z",
  "conditions": [
    {"bucket": "sigv4examplebucket"},
    ["starts-with", "$key", "user/user1/"],
    {"acl": "public-read"},
    {"success_action_redirect": "http://sigv4examplebucket.s3.amazonaws.com/successful_upload.html"},
    ["starts-with", "$Content-Type", "image/"],
    {"x-amz-meta-uuid": "14365123651274"},
    {"x-amz-server-side-encryption": "AES256"},
    ["starts-with", "$x-amz-meta-tag", ""],

    {"x-amz-credential": "AKIAIOSFODNN7EXAMPLE/20151229/us-east-1/s3/aws4_request"},
    {"x-amz-algorithm": "AWS4-HMAC-SHA256"},
    {"x-amz-date": "20151229T000000Z" }
  ]
}`
	encPolicy = "eyAiZXhwaXJhdGlvbiI6ICIyMDE1LTEyLTMwVDEyOjAwOjAwLjAwMFoiLA0KICAiY29uZGl0aW9ucyI6IFsNCiAgICB7ImJ1Y2tldCI6ICJzaWd2NGV4YW1wbGVidWNrZXQifSwNCiAgICBbInN0YXJ0cy13aXRoIiwgIiRrZXkiLCAidXNlci91c2VyMS8iXSwNCiAgICB7ImFjbCI6ICJwdWJsaWMtcmVhZCJ9LA0KICAgIHsic3VjY2Vzc19hY3Rpb25fcmVkaXJlY3QiOiAiaHR0cDovL3NpZ3Y0ZXhhbXBsZWJ1Y2tldC5zMy5hbWF6b25hd3MuY29tL3N1Y2Nlc3NmdWxfdXBsb2FkLmh0bWwifSwNCiAgICBbInN0YXJ0cy13aXRoIiwgIiRDb250ZW50LVR5cGUiLCAiaW1hZ2UvIl0sDQogICAgeyJ4LWFtei1tZXRhLXV1aWQiOiAiMTQzNjUxMjM2NTEyNzQifSwNCiAgICB7IngtYW16LXNlcnZlci1zaWRlLWVuY3J5cHRpb24iOiAiQUVTMjU2In0sDQogICAgWyJzdGFydHMtd2l0aCIsICIkeC1hbXotbWV0YS10YWciLCAiIl0sDQoNCiAgICB7IngtYW16LWNyZWRlbnRpYWwiOiAiQUtJQUlPU0ZPRE5ON0VYQU1QTEUvMjAxNTEyMjkvdXMtZWFzdC0xL3MzL2F3czRfcmVxdWVzdCJ9LA0KICAgIHsieC1hbXotYWxnb3JpdGhtIjogIkFXUzQtSE1BQy1TSEEyNTYifSwNCiAgICB7IngtYW16LWRhdGUiOiAiMjAxNTEyMjlUMDAwMDAwWiIgfQ0KICBdDQp9"
)
