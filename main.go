package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	htemplate "html/template"
	"net/http"
	"os"
	"text/template"
	"time"
)

func main() {
	// Payload is used to fill out the policy template
	type Payload struct {
		Expiration        string
		Bucket            string
		Key               string
		SuccessRedirect   string
		ContentTypeStarts string
		Credential        string
		Date              string
	}
	// Form is used to fill out the html form
	type Form struct {
		Policy    string
		Signature string
		Payload
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		// Create a policy using UTF-8 encoding.
		// Convert the UTF-8-encoded policy to Base64. The result is the string to sign.
		// Create the signature as an HMAC-SHA256 hash of the string to sign. You will provide the signing key as key to the hash function.
		// Encode the signature by using hex encoding.

		now := time.Now().UTC()
		key := os.Getenv("AWS_ACCESS_KEY_ID")
		p := Payload{
			Expiration:        now.Add(24 * time.Hour).Format(time.RFC3339),
			Bucket:            "brianfoshee",
			Key:               "muploads/",
			ContentTypeStarts: "video/",
			Credential:        fmt.Sprintf("%s/%s/us-east-1/s3/aws4_request", key, now.Format("20060102")),
			Date:              now.Format("20060102T150405Z"),
			SuccessRedirect:   "https://www.brianfoshee.com",
		}

		tmpl, err := template.New("test").Parse(payload)
		if err != nil {
			fmt.Println(err)
			return
		}

		b := []byte{}
		buf := bytes.NewBuffer(b)
		if err := tmpl.Execute(buf, p); err != nil {
			fmt.Println(err)
			return
		}

		b64 := base64.StdEncoding

		// policy in base64 (STRING TO SIGN)
		policy := make([]byte, b64.EncodedLen(buf.Len()))
		b64.Encode(policy, buf.Bytes())

		sec := os.Getenv("AWS_SECRET_ACCESS_KEY")

		s256 := sha256.New
		dk := hmac.New(s256, []byte("AWS4"+sec))
		dk.Write([]byte(now.Format("20060102")))

		drk := hmac.New(s256, dk.Sum(nil))
		drk.Write([]byte("us-east-1"))

		drsk := hmac.New(s256, drk.Sum(nil))
		drsk.Write([]byte("s3"))

		signingKey := hmac.New(s256, drsk.Sum(nil))
		signingKey.Write([]byte("aws4_request"))

		signature := hmac.New(s256, signingKey.Sum(nil))
		signature.Write([]byte(policy))

		// encode signature using hex encoding
		encsig := make([]byte, hex.EncodedLen(signature.Size()))
		hex.Encode(encsig, signature.Sum(nil))

		// fill out the form
		f := Form{
			Policy:    string(policy),
			Signature: string(encsig),
			Payload:   p,
		}

		frm, err := htemplate.New("form").Parse(form)
		if err != nil {
			fmt.Println("error parsing html template", err)
			return
		}

		if err := frm.Execute(w, f); err != nil {
			fmt.Println("error executing form", err)
			return
		}
	}

	http.HandleFunc("/", handler)

	http.ListenAndServe("localhost:8080", nil)
}

var payload = `{ "expiration": "{{ .Expiration }}",
  "conditions": [
    {"bucket": "{{ .Bucket }}"},
    ["starts-with", "$key", "{{ .Key }}"],
    {"acl": "public-read"},
    {"success_action_redirect": "{{ .SuccessRedirect }}"},
    ["starts-with", "$Content-Type", "{{ .ContentTypeStarts }}"],
    {"x-amz-credential": "{{ .Credential }}"},
    {"x-amz-algorithm": "AWS4-HMAC-SHA256"},
    {"x-amz-date": "{{ .Date }}" }
  ]
}`

var form = `<!doctype html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
</head>
<body>
<form action="https://brianfoshee.s3.amazonaws.com/" method="post" enctype="multipart/form-data">
    Key to upload:
    <input type="input"  name="key" value="{{ .Key }}${filename}" /><br />
    <input type="hidden" name="acl" value="public-read" />
    <input type="hidden" name="success_action_redirect" value="{{ .SuccessRedirect }}" />
    Content-Type:
    <input type="input"  name="Content-Type" value="{{ .ContentTypeStarts }}" /><br />
    <input type="hidden" name="X-Amz-Credential" value="{{ .Credential }}" />
    <input type="hidden" name="X-Amz-Algorithm" value="AWS4-HMAC-SHA256" />
    <input type="hidden" name="X-Amz-Date" value="{{ .Date }}" />
    <input type="hidden" name="Policy" value='{{ .Policy }}' />
    <input type="hidden" name="X-Amz-Signature" value="{{ .Signature }}" />
	<br />
    File:
    <input type="file"   name="file" /> <br />
    <!-- The elements after this will be ignored -->
    <input type="submit" name="submit" value="Upload to Amazon S3" />
  </form>
</body>
</html>`
