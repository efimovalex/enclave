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
You can customize the key TTL, type and size via headers:
- `X-Key-TTL`: Time to live for the key, e.g. `60m`, `24h`. Default is `30m`.
- `X-Key-Type`: Type of the key, e.g. `kyber` or `rsa`. Default is `kyber`.
- `X-Key-Size`: Size of the key, e.g. `512`, `768`, `1024`. Default is `1024`.

Use the following commands to create a key, encrypt and decrypt a message:
```
$ curl -H "Authorization: Bearer I6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30" \
    -H "X-Key-TTL: 60m" \
    -H "X-Key-Type: kyber" \
    -H "X-Key-Size: 1024" \
    -X POST 'http://localhost:8080/transit/keys/testkey'

$ curl -H "Authorization: Bearer I6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30" \
    -X POST 'http://localhost:8080/transit/encrypt/testkey' \
    -d '{"plaintext":"Hello World!"}' \
    --output cifertext.txt

$ curl -H "Authorization: Bearer I6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30" \
    -X POST 'http://localhost:8080/transit/decrypt/testkey' \
    --data-binary @cifertext.txt
```

You can also create RSA keys:

```
$ curl -H "Authorization: Bearer I6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30" \
    -H "X-Key-TTL: 60m" \
    -H "X-Key-Type: rsa" \
    -H "X-Key-Size: 4096" \
    -X POST 'http://localhost:8080/transit/keys/testkeyrsa'

$ curl -H "Authorization: Bearer I6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30" \
    -X POST 'http://localhost:8080/transit/encrypt/testkeyrsa' \
    -d '{"plaintext":"Hello World!"}' \
    --output cifertext.txt

$ curl -H "Authorization: Bearer I6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30" \
    -X POST 'http://localhost:8080/transit/decrypt/testkeyrsa' \
    --data-binary @cifertext.txt
```

### Run tests

Quick tests run for development:
```
$ make test
```

Slower CI tests that check for code coverage:
```
$ make ci
```

Known issues:
- You can run multiple instances of the server, but the cache peer discovery is not implemented, so the cache will not be shared between instances.
- `make lint` is not working because of golangci-lint version mismatch.
- Auth token is hardcoded in the middleware.go file. This should be replaced with a proper auth mechanism. 
- Missing an env config loader to make the server more configurable.
- Missing other key types, e.g. ECC, ED25519, etc. But can be easily added.