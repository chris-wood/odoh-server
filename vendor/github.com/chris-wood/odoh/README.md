# [Oblivious DoH Library](https://tools.ietf.org/html/draft-pauly-dprive-oblivious-doh)

[![CircleCI](https://circleci.com/gh/chris-wood/odoh.svg?style=svg)](https://circleci.com/gh/chris-wood/odoh)
[![Coverage Status](http://codecov.io/github/chris-wood/odoh/coverage.svg?branch=master)](http://codecov.io/github/chris-wood/odoh?branch=master)
[![GoDoc](https://godoc.org/github.com/chris-wood/odoh?status.svg)](https://godoc.org/github.com/chris-wood/odoh)
[![Go Report Card](https://goreportcard.com/badge/github.com/chris-wood/odoh)](https://goreportcard.com/report/github.com/chris-wood/odoh)

## Test vector generation

To generate test vectors, run:

```
$ ODOH_TEST_VECTORS_OUT=test-vectors.json go test -v -run TestVectorGenerate
```

To check test vectors, run:

```
$ ODOH_TEST_VECTORS_IN=test-vectors.json go test -v -run TestVectorVerify
```
