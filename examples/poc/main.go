package main

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/brianfoshee/s3upload"
)

// Payload is used to fill out the policy template
type Payload struct {
	Expiration string
	Bucket     string
	Key        string

	// Redirect looks like: localhost:8080/?bucket=brianfoshee&key=muploads%2Fcubeprint.mp4&etag=%22aca3de6c6cf590a1f75ef08d939b9eff%22
	SuccessRedirect string

	ContentTypeStarts string
	Credential        string
	Date              string
}

// Form is used to fill out the html form
type Form struct {
	URL       string
	Policy    string
	Signature string
	Payload
}

func main() {
	// be sure to fill out the AWS secret, key, and bucket
	su := s3upload.New("us-east-1", "")
	key := os.Getenv("AWS_ACCESS_KEY_ID")
	bucket := "brianfoshee"

	// parse the template that generates a policy
	tmpl, err := template.New("test").Parse(policyDoc)
	if err != nil {
		fmt.Println(err)
		return
	}
	// parse the template the generates the HTML POST form
	frm, err := template.New("form").Parse(form)
	if err != nil {
		fmt.Println("error parsing html template", err)
		return
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().UTC()

		p := Payload{
			Expiration:        now.Add(24 * time.Hour).Format(time.RFC3339),
			Bucket:            bucket,
			Key:               "muploads/",
			ContentTypeStarts: "video/",
			Credential:        fmt.Sprintf("%s/%s/us-east-1/s3/aws4_request", key, now.Format("20060102")),
			Date:              now.Format("20060102T150405Z"),
			SuccessRedirect:   "http://localhost:8080",
		}

		// fill out the policy doc with Payload data
		b := []byte{}
		buf := bytes.NewBuffer(b)
		if err := tmpl.Execute(buf, p); err != nil {
			fmt.Println(err)
			return
		}

		// generate signature and policy
		policy, signed := su.Sign(buf.Bytes())

		f := Form{
			Policy:    policy,
			Signature: signed,
			URL:       "https://" + bucket + ".s3.amazonaws.com/",
			Payload:   p,
		}

		// fill out the HTML form and write it out to the browser
		if err := frm.Execute(w, f); err != nil {
			fmt.Println("error executing form", err)
			return
		}
	}

	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe("localhost:8080", nil))
}

var policyDoc = `{ "expiration": "{{ .Expiration }}",
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
<form action="{{ .URL }}" method="post" enctype="multipart/form-data">
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
