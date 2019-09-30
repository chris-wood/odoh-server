# odoh-server

(Oblivious) DoH Server

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

# Testing

Locally, using curl:

~~~
$ curl -v "http://localhost:8080/dns-query?dns=YXBwbGUuY29t"
$ curl -v -H "Content-Type:application/dns-message" -X POST -d "YXBwbGUuY29t" "http://localhost:8080/dns-query"
$ curl -v -H "Content-Type:application/dns-message" -X POST --data-binary "@/Volumes/src/oss/go/src/github.com/chris-wood/odoh-client/out" "http://localhost:8080/dns-query"
~~~

("YXBwbGUuY29t" is the base64url-encoding of "apple.com".)

After deployment, using a version of curl with DoH [https://curl.haxx.se/download.html#MacOSX]:

~~~
$ /usr/local/opt/curl/bin/curl -v --doh-url https://odoh-254517.appspot.com/dns-query https://apple.com
~~~
