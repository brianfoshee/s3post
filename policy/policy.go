// http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html
package policy

import (
	"encoding/json"
	"strconv"
	"time"
)

type Policy struct {
	Expiration time.Time
	conditions []condition
}

// Cannot use ConditionMatchRange in here. Use SetRangeCondition for that.
func (p *Policy) SetCondition(k ConditionKey, v string, m ConditionMatch) {
	c := condition{key: k, value: v, match: m}
	p.conditions = append(p.conditions, c)
}

func (p *Policy) SetRangeCondition(k ConditionKey, l, u uint64) {
	c := condition{
		key:        k,
		rangeLower: l,
		rangeUpper: u,
		match:      ConditionMatchRange,
	}
	p.conditions = append(p.conditions, c)
}

// I want to avoid this but how?
type policyJSON struct {
	Expiration string      `json:"expiration"`
	Conditions []condition `json:"conditions"`
}

func (p Policy) MarshalJSON() ([]byte, error) {
	d := policyJSON{
		p.Expiration.Format("2006-01-02T15:04:05.000Z"),
		p.conditions,
	}
	return json.Marshal(d)
}

// Each form field that you specify in a form (except x-amz-signature, file,
// policy, and field names that have an x-ignore- prefix) must appear in the
// list of conditions.
type condition struct {
	key        ConditionKey
	value      string
	rangeLower uint64
	rangeUpper uint64
	match      ConditionMatch
}

func (c condition) MarshalJSON() ([]byte, error) {
	// Exact Matches:
	// {"acl": "public-read" }
	if c.match == ConditionMatchExact {
		m := map[string]string{
			string(c.key): c.value,
		}
		return json.Marshal(m)
	}

	// The other match types are arrays with 3 elements.
	var a [3]string

	if c.match == ConditionMatchStartsWith {
		// Starts With:
		// ["starts-with", "$key", "user/user1/"]
		a[0] = "starts-with"
		a[1] = "$" + string(c.key)
		a[2] = c.value
	} else if c.match == ConditionMatchAny {
		// Matching Any Content
		// ["starts-with", "$success_action_redirect", ""]
		a[0] = "starts-with"
		a[1] = "$" + string(c.key)
		a[2] = ""
	} else if c.match == ConditionMatchRange {
		// Specifying Ranges
		// ["content-length-range", 1048579, 10485760]
		a[0] = string(c.key)
		a[1] = strconv.FormatUint(c.rangeLower, 10)
		a[2] = strconv.FormatUint(c.rangeUpper, 10)
	}

	return json.Marshal(a)
}

// Although you must specify one condition for each form field that you specify
// in the form, you can create more complex matching criteria by specifying
// multiple conditions for a form field.
type ConditionMatch int

const (
	ConditionMatchExact ConditionMatch = iota
	ConditionMatchStartsWith
	ConditionMatchAny
	ConditionMatchRange
)

const AWSV4SignatureAlgorithm = "AWS4-HMAC-SHA256"

type ConditionKey string

// conditions supported by default. See AWS docs for rules when using each.
// TODO Document Support x-amz-meta-*
// TODO Document support x-amz-*
const (
	ConditionKeyACL                   ConditionKey = "acl"
	ConditionKeyBucket                             = "bucket"
	ConditionKeyContentLengthRange                 = "content-length-range"
	ConditionKeyCacheControl                       = "Cache-Control"
	ConditionKeyContentType                        = "Content-Type"
	ConditionKeyContentDisposition                 = "Content-Disposition"
	ConditionKeyContentEncoding                    = "Content-Encoding"
	ConditionKeyExpires                            = "Expires"
	ConditionKeyKey                                = "key"
	ConditionKeySuccessActionRedirect              = "success_action_redirect"
	ConditionKeyRedirect                           = "redirect"
	ConditionKeySuccessActionStatus                = "success_action_status"

	// For AWS Signature Version 4, the value is AWS4-HMAC-SHA256.
	ConditionKeyAMZAlgorithm = "x-amz-algorithm"

	// It is a string of the following form:
	// <your-access-key-id>/<date>/<aws-region>/<aws-service>/aws4_request
	ConditionKeyAMZCredential = "x-amz-credential"

	// The date value specified in the ISO8601 formatted string.
	ConditionKeyAMZDate = "x-amz-date"

	// Amazon DevPay security token.
	ConditionKeyAMZSecurityToken = "x-amz-security-token"
)
