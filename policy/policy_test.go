package policy

import (
	"encoding/json"
	"testing"
	"time"
)

func TestPolicy(t *testing.T) {
	p := Policy{
		Expiration: time.Date(2015, 12, 30, 12, 0, 0, 0, time.UTC),
	}
	p.SetCondition(ConditionBucket, "sigv4examplebucket", ConditionMatchExact)
	p.SetCondition(ConditionKey, "user/user1/", ConditionMatchStartsWith)
	p.SetCondition(ConditionACL, "public-read", ConditionMatchExact)
	p.SetCondition(
		ConditionSuccessActionRedirect,
		"http://sigv4examplebucket.s3.amazonaws.com/successful_upload.html",
		ConditionMatchExact,
	)
	p.SetCondition(
		ConditionContentType,
		"image/",
		ConditionMatchStartsWith,
	)
	p.SetCondition(
		"x-amz-meta-uuid",
		"14365123651274",
		ConditionMatchExact,
	)
	p.SetCondition(
		"x-amz-server-side-encryption",
		"AES256",
		ConditionMatchExact,
	)
	p.SetCondition(
		"x-amz-meta-tag",
		"",
		ConditionMatchStartsWith,
	)
	p.SetCondition(
		ConditionAMZCredential,
		"AKIAIOSFODNN7EXAMPLE/20151229/us-east-1/s3/aws4_request",
		ConditionMatchExact,
	)
	p.SetCondition(
		ConditionAMZAlgorithm,
		AWSV4SignatureAlgorithm,
		ConditionMatchExact,
	)
	p.SetCondition(
		ConditionAMZDate,
		"20151229T000000Z",
		ConditionMatchExact,
	)

	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}

	if string(b) != policyDocWants {
		t.Errorf("wanted: \n %s \n got: \n %s \n", policyDocWants, string(b))
	}
}

const policyDocWants = `{"expiration":"2015-12-30T12:00:00.000Z","conditions":[{"bucket":"sigv4examplebucket"},["starts-with","$key","user/user1/"],{"acl":"public-read"},{"success_action_redirect":"http://sigv4examplebucket.s3.amazonaws.com/successful_upload.html"},["starts-with","$Content-Type","image/"],{"x-amz-meta-uuid":"14365123651274"},{"x-amz-server-side-encryption":"AES256"},["starts-with","$x-amz-meta-tag",""],{"x-amz-credential":"AKIAIOSFODNN7EXAMPLE/20151229/us-east-1/s3/aws4_request"},{"x-amz-algorithm":"AWS4-HMAC-SHA256"},{"x-amz-date":"20151229T000000Z"}]}`
