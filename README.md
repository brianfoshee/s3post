[![Build Status](https://travis-ci.org/brianfoshee/s3upload.png)](https://travis-ci.org/brianfoshee/s3upload)

Package s3upload signs S3 POST policy documents for browser-based file uploads
to AWS S3.
More details on that can be found in the [AWS docs][docs].

### Usage

To use this package, generate a POST policy document, then pass that policy into
the Sign method to receive a signature to be used in a POST form.

Details on
Policy details here http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html

See the examples folder for complete usage.

### Signature details

The policy document is signed using this calculation:

[![Signature Calculation](http://docs.aws.amazon.com/AmazonS3/latest/API/images/sigV4-post.png)](http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-UsingHTTPPOST.html#sigv4-post-signature-calc)

[docs]: http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-UsingHTTPPOST.html
