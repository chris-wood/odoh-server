test:
	go test ./...

logs-target:
	gcloud app logs tail -s odoh-target

lggs-proxy:
	gcloud app logs tail -s odoh-proxy

deploy-target:
	gcloud app deploy --stop-previous-version target.yaml

deploy-proxy:
	gcloud app deploy --stop-previous-version proxy.yaml