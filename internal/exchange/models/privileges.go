package models

import "github.com/DIMO-Network/dauth/pkg/tokenclaims"

const (
	// TypeCloudEvent is the type of agreement for a cloud event.
	TypeCloudEvent = "cloudevent"
	// TypePermission is the type of agreement for a permission.
	TypePermission = "permission"
	// GlobalIdentifier is the global identifier for a cloud event.
	GlobalIdentifier = tokenclaims.GlobalIdentifier
)

type EventFilter struct {
	EventType string   `json:"eventType"`
	Source    string   `json:"source"`
	IDs       []string `json:"ids"`
	Tags      []string `json:"tags"`
}
