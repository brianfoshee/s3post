package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/brianfoshee/s3post"
	"github.com/brianfoshee/s3post/policy"
)

func main() {
	// Create the policy
	p := policy.Policy{
		Expiration: time.Date(2007, 12, 01, 12, 0, 0, 0, time.UTC),
	}
	p.SetCondition(policy.ConditionACL, "public-read", policy.ConditionMatchExact)
	p.SetCondition(policy.ConditionBucket, "johnsmith", policy.ConditionMatchExact)
	p.SetCondition(policy.ConditionKey, "user/eric/", policy.ConditionMatchStartsWith)

	// Serialize the policy as a JSON document (as expected by AWS S3).
	b, err := json.Marshal(p)
	if err != nil {
		fmt.Println("Issue marshaling policy")
	}

	s := s3post.New("us-east-1", os.Getenv("AWS_SECRET_KEY_ID"))
	// pass the policy into the AWS signing algorithm
	encodedPolicy, signature := s.Sign(b)

	// Use the signedPolicy and signature in a form for uploading.
	// See examples/supply-policy for a complete html rendered form.
	fmt.Println(encodedPolicy)
	fmt.Println(signature)

}
