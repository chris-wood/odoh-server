module github.com/chris-wood/odoh-server

go 1.14

// +heroku goVersion go1.14
// +scalingo goVersion go1.14

require (
	cloud.google.com/go v0.61.0 // indirect
	cloud.google.com/go/logging v1.0.0
	github.com/chris-wood/odoh v0.0.0-20200904213540-aa350f1a2166
	github.com/cisco/go-hpke v0.0.0-20200710171132-37d332d5f613
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/elastic/go-elasticsearch/v8 v8.0.0-20200716073932-4f0b75746dc1
	github.com/google/go-cmp v0.5.1 // indirect
	github.com/miekg/dns v1.1.31
	golang.org/x/sys v0.0.0-20200728102440-3e129f6d46b1 // indirect
	google.golang.org/genproto v0.0.0-20200730144737-007c33dbd381 // indirect
	google.golang.org/grpc v1.31.0 // indirect
)
