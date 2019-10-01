test:
	go test ./...

logs:
	gcloud app logs tail -s default

deploy:
	gcloud app deploy --stop-previous-version app.yaml