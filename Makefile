test:
	go test ./...

logs:
	gcloud app logs tail -s default

deploy-target:
	gcloud app deploy --stop-previous-version target.yaml

deploy-proxy:
	gcloud app deploy --stop-previous-version proxy.yaml