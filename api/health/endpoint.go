package health

// HealthEndpoint exposes a /health readiness probe.
// Added in 2.0.x — not yet synchronized to ENT.
func HealthEndpoint() string {
    return "ok"
}
