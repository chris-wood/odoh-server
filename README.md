# odoh-server

[Oblivious DoH Server](https://tools.ietf.org/html/draft-pauly-dprive-oblivious-doh)

# Usage

To deploy, run:

~~~
$ gcloud app deploy proxy.yaml
...
$ gcloud app deploy target.yaml
...
~~~

To check on its status, run:

~~~
$ gcloud app browse
~~~

To stream logs when deployed, run

~~~
$ gcloud app logs tail -s default
~~~

To run locally build and run the project using

```shell
go build
PORT=8080 ./odoh_server
```

## Reverse proxy

You need to deploy a reverse proxy with a valid TLS server certificate
for clients to be able to authenticate the target or proxy.

The simplest option for this is using [Caddy](https://caddyserver.com).
Caddy will automatically provision a TLS certificate using ACME from [Let's Encrypt](https://letsencrypt.org).

For instance:

```
caddy reverse-proxy --from https://odoh.example.net:443 --to 127.0.0.1:8080
```

Alternatively, use a Caddyfile similar to:

```
odoh.example.net

reverse_proxy localhost:8080
```
and run `caddy start`.
