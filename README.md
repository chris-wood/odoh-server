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

# Testing

Locally:

~~~
curl -v "http://localhost:8080/dns-query?dns=YXBwbGUuY29t"
~~~


After deployment:

~~~
/usr/local/opt/curl/bin/curl -v --doh-url https://odoh-254517.appspot.com/odoh https://apple.com
~~~


https://curl.haxx.se/download.html#MacOSX
https://github.com/dnscrypt/dnscrypt-proxy/releases/tag/2.0.27