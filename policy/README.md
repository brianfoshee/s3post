Package policy provides functionality to create a POST policy for uploading a
file directly from a browser to S3.

More details for creating a policy can be found in [Amazon's docs][docs].

### Usage

Here's how to create the following Policy document (taken from the AWS docs).

```json
{ "expiration": "2007-12-01T12:00:00.000Z",
  "conditions": [
    {"acl": "public-read" },
    {"bucket": "johnsmith" },
    ["starts-with", "$key", "user/eric/"],
  ]
}
```

```go
p := policy.Policy{
	Expiration: time.Date(2007, 12, 01, 12, 0, 0, 0, time.UTC),
}
p.SetCondition(policy.ConditionACL, "public-read", policy.ConditionMatchExact)
p.SetCondition(policy.ConditionBucket, "johnsmith", policy.ConditionMatchExact)
p.SetCondition(policy.ConditionKey, "user/eric/", policy.ConditionStartsWith)
b, err := json.Marshal(p)
// handle err

// sign the policy
s := s3post.New("", "")
enc, signed := s.Sign(b)

```

See the examples folder for an end-to-end demonstration of rendering a form to
be used for uploading.

[docs]: http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html
