// Package s3upload provides a function to sign a S3 POST upload policy
package s3upload

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"time"
)

// S3Upload holds information necessary for signing policy documents.
type S3Upload struct {
	awsRegion string
	awsSecret string
}

// New returns an instance of S3Upload that uses the passed in region and
// secret. If either is empty, environment variables will be used.
func New(region, secret string) *S3Upload {
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if secret == "" {
		secret = os.Getenv("AWS_SECRET_ACCESS_KEY")
	}
	s := &S3Upload{
		awsRegion: region,
		awsSecret: secret,
	}
	return s
}

// We need to be able to fake the current time in tests. This allows us to
// reimplement now with a function that returns the exact date we want.
var now = time.Now

// Sign takes a POST policy and outputs the signed version of the policy as
// well as a signature to include in the POST form.
//
// Signature is created by the calculation process here:
// http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-authentication-HTTPPOST.html
//
// Returns the base64-encoded policy and the hex-encoded and signed policy.
// If an error occurs two empty strings will be returned.
func (s *S3Upload) Sign(policy []byte) (string, string) {
	// policy encoded in base64 (String to Sign)
	stringToSign := make([]byte, base64.StdEncoding.EncodedLen(len(policy)))
	base64.StdEncoding.Encode(stringToSign, policy)

	// DateKey = HMACSHA256("AWS4"+awsSecret, "yyyymmdd")
	dk := hmac.New(sha256.New, []byte("AWS4"+s.awsSecret))
	_, err := dk.Write([]byte(now().UTC().Format("20060102")))
	if err != nil {
		return "", ""
	}

	// DateRegionKey = HMACSHA256(DateKey, awsRegion)
	drk := hmac.New(sha256.New, dk.Sum(nil))
	_, err = drk.Write([]byte(s.awsRegion))
	if err != nil {
		return "", ""
	}

	// DateRegionServiceKey = HMACSHA256(DateRegionKey, "s3")
	drsk := hmac.New(sha256.New, drk.Sum(nil))
	_, err = drsk.Write([]byte("s3"))
	if err != nil {
		return "", ""
	}

	// SigningKey = HMACSHA256(DateRegionServiceKey, "aws4_request")
	signingKey := hmac.New(sha256.New, drsk.Sum(nil))
	_, err = signingKey.Write([]byte("aws4_request"))
	if err != nil {
		return "", ""
	}

	// Signature = HMACSHA256(SigningKey, StringToSign)
	signature := hmac.New(sha256.New, signingKey.Sum(nil))
	_, err = signature.Write([]byte(stringToSign))
	if err != nil {
		return "", ""
	}

	// encode signature using hex encoding
	encsig := make([]byte, hex.EncodedLen(signature.Size()))
	hex.Encode(encsig, signature.Sum(nil))

	return string(stringToSign), string(encsig)
}
