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

// Signed holds both the base64 encoded policy document and the hex encoded
// signature to be sent off with a POST form.
type Signed struct {
	Policy    string
	Signature string
}

// We need to be able to fake the current time in tests. This allows us to
// reimplement now with a function that returns the exact date we want.
var now = time.Now

// Sign takes a POST policy and outputs the signed version of the policy as
// well as a signature to include in the POST form.
//
// Signature is created by the calculation process here:
// http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-authentication-HTTPPOST.html
func (s *S3Upload) Sign(policy []byte) Signed {
	b64 := base64.StdEncoding
	s256 := sha256.New

	// policy encoded in base64 (String to Sign)
	stringToSign := make([]byte, b64.EncodedLen(len(policy)))
	b64.Encode(stringToSign, policy)

	// DateKey = HMACSHA256("AWS4"+awsSecret, "yyyymmdd")
	dk := hmac.New(s256, []byte("AWS4"+s.awsSecret))
	dk.Write([]byte(now().UTC().Format("20060102")))

	// DateRegionKey = HMACSHA256(DateKey, awsRegion)
	drk := hmac.New(s256, dk.Sum(nil))
	drk.Write([]byte(s.awsRegion))

	// DateRegionServiceKey = HMACSHA256(DateRegionKey, "s3")
	drsk := hmac.New(s256, drk.Sum(nil))
	drsk.Write([]byte("s3"))

	// SigningKey = HMACSHA256(DateRegionServiceKey, "aws4_request")
	signingKey := hmac.New(s256, drsk.Sum(nil))
	signingKey.Write([]byte("aws4_request"))

	// Signature = HMACSHA256(SigningKey, StringToSign)
	signature := hmac.New(s256, signingKey.Sum(nil))
	signature.Write([]byte(stringToSign))

	// encode signature using hex encoding
	encsig := make([]byte, hex.EncodedLen(signature.Size()))
	hex.Encode(encsig, signature.Sum(nil))

	d := Signed{
		Policy:    string(stringToSign),
		Signature: string(encsig),
	}

	return d
}
