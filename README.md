[![Build Status](https://travis-ci.org/brianfoshee/s3upload.png)](https://travis-ci.org/brianfoshee/s3upload)

To use this, generate a JSON policy based off the S3Policy struct (probably using
html/template - see example for details). Then pass that policy into some func to
have it spit out the signed policy and signature.
POlicy details here http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html

The tests get their info from this AWS example, those aren't my S3 credentials:
http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-post-example.html
