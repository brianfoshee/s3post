[![Build Status](https://travis-ci.org/brianfoshee/s3upload.png)](https://travis-ci.org/brianfoshee/s3upload)

// TODO: make this nicer

Zero external dependencies. Uses ___ this signature method to sign policies.

To use this, generate a JSON policy based off the S3Policy struct (probably using
html/template - see example for details). Then pass that policy into some func to
have it spit out the signed policy and signature.
POlicy details here http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html

// TODO: mention the examples
// TODO: add readme for the examples
// TODO: clean up examples
