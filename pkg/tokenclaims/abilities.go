package tokenclaims

// The ability vocabulary (design spec §5.1). Historical abilities are checked
// against data timestamps and carry windows in a grant; live abilities are
// checked at the time of the request and carry none.
const (
	// AbilityTelemetryRead reads non-location signals.
	AbilityTelemetryRead = "telemetry:read"
	// AbilityHealthRead reads health and diagnostic signals.
	AbilityHealthRead = "health:read"
	// AbilityLocationPrecise reads location as recorded.
	AbilityLocationPrecise = "location:precise"
	// AbilityLocationApproximate reads location coarsened.
	AbilityLocationApproximate = "location:approximate"
	// AbilityEventsRead reads decoded events.
	AbilityEventsRead = "events:read"
	// AbilityDocumentsRead reads documents and credentials about the vehicle.
	AbilityDocumentsRead = "documents:read"
	// AbilityRawRead reads the raw payloads behind the decoded data.
	AbilityRawRead = "raw:read"

	// AbilityStreamLive subscribes to live data.
	AbilityStreamLive = "stream:live"
	// AbilityCommandLock and friends make the vehicle do something.
	AbilityCommandLock   = "command:lock"
	AbilityCommandUnlock = "command:unlock"
	AbilityCommandCharge = "command:charge"
)
