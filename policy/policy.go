// Package policy provides functionlity to create a POST policy for uploading a
// file directly from a browser to S3.
package policy

import (
	"encoding/json"
	"strconv"
	"time"
)

// AWSV4SignatureAlgorithm is the value typically used for the x-amz-algorithm
// condition key.
const AWSV4SignatureAlgorithm = "AWS4-HMAC-SHA256"

// ConditionMatch can be one of the four condition matching types that can be
// used in a POST policy.
type ConditionMatch int

const (
	// ConditionMatchExact is to be used when a condition must match the
	// exact value specified. Output ex: `{"acl": "public-read" }`.
	ConditionMatchExact ConditionMatch = iota

	// ConditionMatchStartsWith is to be used when a condition must start with
	// the specified value. Output Ex: `["starts-with", "$key", "user/user1/"]`
	ConditionMatchStartsWith

	// ConditionMatchAny allows a form field to accept any value. Output ex:
	// `["starts-with", "$success_action_redirect", ""]`.
	ConditionMatchAny

	// ConditionMatchRange is to be used when a form field must accept a range
	// of values. Output ex: `["content-length-range", 1048579, 10485760]`.
	ConditionMatchRange
)

// Condition elements supported by default. See AWS docs for rules when using
// each.
// If you need to use x-amz-meta-* or x-amz-* condition elements you can pass
// those as strings to SetCondition.
const (
	ConditionACL                   string = "acl"
	ConditionBucket                       = "bucket"
	ConditionContentLengthRange           = "content-length-range"
	ConditionCacheControl                 = "Cache-Control"
	ConditionContentType                  = "Content-Type"
	ConditionContentDisposition           = "Content-Disposition"
	ConditionContentEncoding              = "Content-Encoding"
	ConditionExpires                      = "Expires"
	ConditionKey                          = "key"
	ConditionSuccessActionRedirect        = "success_action_redirect"
	ConditionRedirect                     = "redirect"
	ConditionSuccessActionStatus          = "success_action_status"
	ConditionAMZAlgorithm                 = "x-amz-algorithm"
	ConditionAMZCredential                = "x-amz-credential"
	ConditionAMZDate                      = "x-amz-date"
	ConditionAMZSecurityToken             = "x-amz-security-token"
)

// Policy represents an AWS POST policy.
// More specifics on what a policy should include can be found here:
// http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html
type Policy struct {
	// The expiration field specifies the expiration date and time of the
	// POST policy in ISO8601 GMT date format.
	Expiration time.Time

	// conditions should only be set with SetCondition or SetRangeCondition.
	conditions []condition
}

// SetCondition adds a POST policy condition to the policy.
//
// Although you must specify one condition for each form field that you specify
// in the form, you can create more complex matching criteria by specifying
// multiple conditions for a form field.
//
// ConditionMatchRange cannot be used in here. Use SetRangeCondition for that.
func (p *Policy) SetCondition(k, v string, m ConditionMatch) {
	c := condition{key: k, value: v, match: m}
	p.conditions = append(p.conditions, c)
}

// SetRangeCondition adds a POST policy condition requiring a range of numbers
// to the policy. This is only used for ConditionMatchRange.
func (p *Policy) SetRangeCondition(k string, l, u uint64) {
	c := condition{
		key:        k,
		rangeLower: l,
		rangeUpper: u,
		match:      ConditionMatchRange,
	}
	p.conditions = append(p.conditions, c)
}

// policyJSON is needed to convert the Expiration time into a string inside of
// MarshalJSON.
type policyJSON struct {
	Expiration string      `json:"expiration"`
	Conditions []condition `json:"conditions"`
}

// MarshalJSON generates a policy document as AWS expects it. The Expiration
// is formatted properly internally.
func (p Policy) MarshalJSON() ([]byte, error) {
	d := policyJSON{
		p.Expiration.Format("2006-01-02T15:04:05.000Z"),
		p.conditions,
	}
	return json.Marshal(d)
}

// condition holds an object which is used to validate a POST request.
// Each form field that you specify in a form (except x-amz-signature, file,
// policy, and field names that have an x-ignore- prefix) must appear in the
// list of conditions.
type condition struct {
	key        string
	value      string
	rangeLower uint64
	rangeUpper uint64
	match      ConditionMatch
}

// MarshalJSON determines how a condition should be represented in a policy and
// converts that representation to JSON.
func (c condition) MarshalJSON() ([]byte, error) {
	// Exact Matches:
	// {"acl": "public-read" }
	if c.match == ConditionMatchExact {
		m := map[string]string{
			c.key: c.value,
		}
		return json.Marshal(m)
	}

	// The other match types are arrays with 3 elements.
	var a [3]string

	if c.match == ConditionMatchStartsWith {
		// Starts With:
		// ["starts-with", "$key", "user/user1/"]
		a[0] = "starts-with"
		a[1] = "$" + c.key
		a[2] = c.value
	} else if c.match == ConditionMatchAny {
		// Matching Any Content
		// ["starts-with", "$success_action_redirect", ""]
		a[0] = "starts-with"
		a[1] = "$" + c.key
		a[2] = ""
	} else if c.match == ConditionMatchRange {
		// Specifying Ranges
		// ["content-length-range", 1048579, 10485760]
		a[0] = c.key
		a[1] = strconv.FormatUint(c.rangeLower, 10)
		a[2] = strconv.FormatUint(c.rangeUpper, 10)
	}

	return json.Marshal(a)
}
