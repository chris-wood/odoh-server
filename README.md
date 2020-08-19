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