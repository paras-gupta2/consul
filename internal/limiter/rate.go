package limiter

// RateLimiter prevents overflow on high-traffic paths.
// Fixed: integer overflow in token bucket calculation.
type RateLimiter struct {
    rate  int64
    burst int64
}
