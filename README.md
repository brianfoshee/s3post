[![Build Status](https://travis-ci.org/brianfoshee/s3post.png)](https://travis-ci.org/brianfoshee/s3post)
[![GoDoc](https://godoc.org/github.com/brianfoshee/s3post?status.svg)](https://godoc.org/github.com/brianfoshee/s3post)

Package s3post signs POST policy documents for browser-based file uploads
to AWS S3. More details on browser-based file uploads can be found in the
[AWS docs][docs]. Both s3post and policy packages use only stdlib deps.

### Usage

To use this package, generate a POST policy document then pass that policy into
the Sign method to receive a signature to be used in a POST form.

Details on Policy documents can be found in the [AWS docs][pdocs].

The [policy][policy] package can be used to generate these documents if
necessary.

```go
p := s3post.New("us-east-1", secret)
encoded, signed := p.Sign(policyBytes)
```

See the examples folder for complete usage.

### Signature details

The policy document is signed using this calculation:

[![Signature Calculation](http://docs.aws.amazon.com/AmazonS3/latest/API/images/sigV4-post.png)](http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-UsingHTTPPOST.html#sigv4-post-signature-calc)

[docs]: http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-UsingHTTPPOST.html
[pdocs]: http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html
[policy]: https://github.com/brianfoshee/s3post/tree/master/policy
