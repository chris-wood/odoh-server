test:
	go test ./...

deploy:
	gcloud app deploy app.yaml