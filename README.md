# Coding Challenge 1

Cahe with concurrency and dedup support and retry logic.

## Example usage
```
import (
    "context"
    "enclave-task1/pkg/cache"
)

func main() {
    ctx := context.Background()
    cache := cache.New()
    data, err := cache.Fetch(ctx, "https://example.com")
    if err != nil {
        panic(err)
    }
    fmt.Println(string(data))
}

```

Run tests:
```
$ cd task1 && go test -v ./...
```


# Coding Challenge 2: Ephemeral Keyber API

## Example usage

### Build and run the server
```
$ cd task2
$ make build
$ ./build/kyberAPI
```

Or simply run:
```
$ make run
```

The server will start on port 8080.

Server uses the mailgun groupcache as memory storage, which can be configured to host multiple instances of the server and share the cache between them.

### Make requests
```
$ curl -H "Authorization: Bearer I6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30" \
    -X POST 'http://localhost:8080/transit/keys/testkey'

$ curl -H "Authorization: Bearer I6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30" \
    -X POST 'http://localhost:8080/transit/encrypt/testkey' \
    -d '{"plaintext":"Hello World!"}' \
    --output cifertext.txt

$ curl -H "Authorization: Bearer I6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30" \
    -X POST 'http://localhost:8080/transit/decrypt/testkey' \
    --data-binary @cifertext.txt
```

### Run tests

Quick tests run for development:
```
$ make test
```

Slower CI tests that check for code coverage:
```
$ make test-ci
```

Known issues:
- You can run multiple instances of the server, but the cache peer discovery is not implemented, so the cache will not be shared between instances.
- `make lint` is not working because of golangci-lint version mismatch.
- Auth token is hardcoded in the middleware.go file. This should be replaced with a proper auth mechanism. 
- Missing a env/