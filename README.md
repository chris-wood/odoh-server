# odoh-server

[Oblivious DoH Server](https://tools.ietf.org/html/draft-pauly-dprive-oblivious-doh)

# Usage

To deploy, run:

~~~
$ gcloud app deploy app.yaml
~~~

To check on its status, run:

~~~
$ gcloud app browse
~~~

To stream logs when deployed, run

~~~
$ gcloud app logs tail -s default
~~~
