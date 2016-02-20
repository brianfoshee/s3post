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
		now := time.Now().UTC()
		key := ""
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

		sec := ""

		// Create a policy using UTF-8 encoding.
		// Convert the UTF-8-encoded policy to Base64. The result is the string to sign.
		// Create the signature as an HMAC-SHA256 hash of the string to sign. You will provide the signing key as key to the hash function.
		// Encode the signature by using hex encoding.

		// create signing key
		signKey := hmac.New(sha256.New, []byte("AWS4"+sec))
		signKey.Write([]byte(now.Format("20060102")))
		signKey.Write([]byte("us-east-1"))
		signKey.Write([]byte("s3"))
		signKey.Write([]byte("aws4_request"))
		// hash the signing key with the base64'd policy - this is the signature
		signKey.Write(policy)

		// encode signature using hex encoding
		signature := make([]byte, hex.EncodedLen(signKey.Size()))
		hex.Encode(signature, signKey.Sum(nil))

		// fill out the form
		f := Form{
			Policy:    string(policy),
			Signature: string(signature),
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

/*
{ "expiration": "2015-12-30T12:00:00.000Z",
  "conditions": [
    {"bucket": "sigv4examplebucket"},
    ["starts-with", "$key", "user/user1/"],
    {"acl": "public-read"},
    {"success_action_redirect": "http://sigv4examplebucket.s3.amazonaws.com/successful_upload.html"},
    ["starts-with", "$Content-Type", "image/"],

    {"x-amz-credential": "AKIAIOSFODNN7EXAMPLE/20151229/us-east-1/s3/aws4_request"},
    {"x-amz-algorithm": "AWS4-HMAC-SHA256"},
    {"x-amz-date": "20151229T000000Z" }
  ]
}
*/

/*

  def request_equirect_upload
    s3_options = Pano.default_s3_options
    policy = @pano.create_s3_policy(ENV["S3_BUCKET"], s3_options)
    signature = @pano.create_s3_signature(ENV["S3_SECRET"], policy)
    data = {
      :post_to        => "https://s3.amazonaws.com/#{ENV["S3_BUCKET"]}/",
      :signature      => signature,
      :acl            => s3_options[:acl],
      :policy         => policy,
      :AWSAccessKeyId => ENV["S3_KEY"],
      :key            => "tours/#{@pano.id}/images/equirect.jpg",
      :pano           => {:id => @pano.id}
    }
  end

  def create_s3_policy(bucket, options)
    str = "{'expiration': '#{options[:expiration_date]}',
      'conditions': [
        {'bucket': '#{bucket}'},
        {'acl': '#{options[:acl]}'},
        {'success_action_status': '201'},
        ['content-length-range', 0, #{options[:max_filesize]}],
        ['starts-with', '$key', 'tours/#{self.id}/images'],"

    if options[:add_web_params] == true
      str += "['starts-with', '$Content-Type', '#{options[:content_type]}'],
      ['starts-with', '$name', ''],
      ['starts-with', '$Filename', ''],"
    end

    str += "]}"

    Base64.encode64(str).gsub(/\n|\r/, '')
  end

  def create_s3_signature(key, policy)
    Base64.encode64(
      OpenSSL::HMAC.digest(
        OpenSSL::Digest::Digest.new('sha1'),
        key, policy)).gsub("\n","")
  end

  def self.default_s3_options
    options = {}
    options[:acl] ||= 'private'
    options[:expiration_date] ||= 10.hours.from_now.utc.iso8601
    options[:max_filesize] ||= 100.megabytes
    options[:content_type] ||= 'image/' # Videos would be binary/octet-stream
    options[:filter_title] ||= 'Images'
    options[:filter_extentions] ||= 'jpg'
    options
  end
*/
