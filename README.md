# traefik-cluster-ratelimit

Traefik comes with a default [rate limiter](https://doc.traefik.io/traefik/middlewares/http/ratelimit/) middleware, but the rate limiter doesn't share a state if you are using several instance of Traefik (think kubernetes HA deployment for example).

This plugin is here to solve this issue: using a Redis as a common state, this plugin implement the [token bucket algorithm](https://en.wikipedia.org/wiki/Token_bucket).

## Configuration

You need to setup the static and dynamic configuration

The following declaration (given here in YAML) defines the plugin:

```yml
# Static configuration

experimental:
  plugins:
    clusterRatelimit:
      moduleName: "github.com/fellowapp/traefik-cluster-ratelimit"
      version: "v1.1.1"
```

Here is an example of a file provider dynamic configuration (given here in YAML), where the interesting part is the http.middlewares section:

```yml
# Dynamic configuration

http:
  routers:
    my-router:
      rule: host(`demo.localhost`)
      service: service-foo
      entryPoints:
        - web
      middlewares:
        - my-middleware

  services:
   service-foo:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:5000
  
  middlewares:
    my-middleware:
      plugin:
        clusterRatelimit:
          average: 50
          burst: 100
```

With a kubernetesingress provider:

```yml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: clusterratelimit
  namespace: ingress-traefik
spec:
  clusterRatelimit:
    average: 100
    burst: 200
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: example-ingress
  namespace: ingress-traefik
  annotations:
    traefik.ingress.kubernetes.io/router.middlewares: ingress-traefik-clusterratelimit@kubernetescrd
spec:
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: example-service
            port:
              number: 80
```

## Extra configuration

The `average` and the `burst` are the number of allowed connection per second, there are other variables:

| Variable                    | Description                                        | default    |
|-----------------------------|----------------------------------------------------|------------|
| period                      | the period (in seconds) of the rate limiter window | 1          |
| average                     | allowed requests per "period" ( 0 = unlimited)     |            |
| burst                       | allowed burst requests per "period"                |            |
| whitelistedIPs              | list of IPs (or CIDR ranges) that bypass rate limiting |        |
| redisAddress                | address of the redis server                        | redis:6379 |
| redisDb                     | redis db to use                                    | 0          |
| redisPassword               | redis authentication (if any)                      |            |
| sourceCriterion.*           | defines what criterion is used to group requests. See next | ipStrategy |
| sourceCriterion.ipStrategy  | client IP based source                             |            |
| sourceCriterion.ipStrategy.depth | tells Traefik to use the X-Forwarded-For header and select the IP located at the depth position |    |
| sourceCriterion.ipStrategy.excludedIPs | list of X-Forwarded-For IPs that are to be excluded | |
| sourceCriterion.requestHost | based source on request host                       |            |
| sourceCriterion.requestHeaderName | Name of the header used to group incoming requests|       |
| sourceCriterion.secure | Whether to securely hash header values (e.g., for authorization tokens). This only applies to uses of sourceCriterion.requestHeaderName | true      |
| breakerThreshold            | number of failed connection before pausing Redis   | 3          |
| breakerReattempt            | nb seconds before attempting to reconnect to Redis | 15         |
| redisConnectionTimeout      | redis connection timeout (in seconds)              | 2          |

Notes:
- for more information about sourceCriteron check the Traefik [ratelimit](https://doc.traefik.io/traefik/middlewares/http/ratelimit/) page
- regarding redispassword, if you dont want to set it in clear text in the traefik configuration, you can specify a variable name starting with '$'. For example `$REDIS_PASSWORD` will use the `REDIS_PASSWORD` environment variable
- `whitelistedIPs` accepts both individual IPs (`192.168.1.5`) and CIDR ranges (`10.0.0.0/8`). Requests from whitelisted IPs bypass rate limiting entirely

A full example would be

```yml
# Dynamic configuration

http:
  ...
  middlewares:
    my-middleware:
      plugin:
        clusterRatelimit:
          average: 5
          burst: 10
          period: 10
          whitelistedIPs:
          - 192.168.1.100
          - 10.0.0.0/8
          sourceCriterion:
            ipStrategy:
              depth: 2
              excludedIPs:
              - 127.0.0.1/32
              - 192.168.1.7          
          redisAddress: redis:6379
          redisPassword: $REDIS_AUTH_PASSWORD
          redisConnectionTimeout: 2
```

## Using Authorization Headers for Rate Limiting

When rate limiting by sensitive headers like Authorization, the `sourceCriterion.secure` option ensures that the actual token values are never stored in Redis as plain text. Instead, they are securely hashed using SHA-256:

```yml
http:
  middlewares:
    auth-rate-limiter:
      plugin:
        clusterRatelimit:
          average: 10
          burst: 20
          sourceCriterion:
            requestHeaderName: "Authorization" 
            secure: true  # Default is true, but shown here for clarity
```

This configuration will limit requests based on the value of the Authorization header while keeping the tokens secure in Redis.

## Redis Memory Management

The rate limiter automatically sets expiration times (TTL) on all Redis keys it creates:

- Each rate limit key is set with a TTL equal to the token bucket's reset time
- The TTL is dynamically calculated based on your configured `rate`, `burst`, and `period` settings
- When requests stop coming from a source, its corresponding keys automatically expire
- No manual cleanup is required, preventing Redis memory leaks

### How the TTL is Calculated

The plugin implements the [Token Bucket Algorithm](https://en.wikipedia.org/wiki/Token_bucket) where:

1. Each source (IP/header) has its own "bucket" with tokens representing available requests
2. The TTL is tied to the "Theoretical Arrival Time" (TAT) - the time when the bucket will be fully replenished
3. The formula is essentially: `TTL = new_tat - current_time`

For example:

- With `average: 10, period: 1, burst: 20`: A source that consumes all 20 burst tokens will have a key with TTL of approximately 2 seconds (time to refill from 0 to 20 at 10 tokens/second)
- With `average: 30, period: 60, burst: 60`: A source consuming all tokens would get a TTL of about 120 seconds (time to refill at 0.5 tokens/second)

### Memory Implications

This TTL mechanism has several advantages:

- **Automatic Cleanup**: Inactive sources naturally disappear from Redis after their TTL expires
- **Bounded Memory Usage**: Redis memory grows proportionally to active users, not historical users
- **Self-Regulating**: Higher rate limits create longer-lived keys, and vice versa
- **Time-Appropriate Storage**: The more aggressively a client consumes their rate limit, the longer their key persists

Under the hood, the Lua script handles the TTL setting:

```lua
local reset_after = new_tat - now
if reset_after > 0 then
  redis.call("SET", rate_limit_key, new_tat, "EX", math.ceil(reset_after))
end
```

When the key expires, it does so naturally through Redis's expiration mechanism without requiring additional cleanup operations.

## Circuit-breaker

If the Redis server is not available, we will stop talking to it, and let pass through.
As mentionned above there are 2 variables you can use to change the default behaviour: `breakerThreshold` and `breakerReattempt`. Usually you dont need to tweak that.

## Benchmark

You can test traefik with the rate limiter with some tools. For example with vegeta (you probably need to install it):
```sh
docker-compose up -d

echo "GET http://localhost:8000/" | vegeta attack -duration=5s -rate=200 | tee results.bin | vegeta report
```
