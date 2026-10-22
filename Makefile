run:
	go run ./cmd/yyb-auth-service

fmt:
	gofmt -w ./cmd ./internal
