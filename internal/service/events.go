package service

import (
	"context"
	"log/slog"
	"time"
)

// Domain event types published by the services.
const (
	EventUserRegistered    = "user.registered"
	EventLoginSucceeded    = "user.login_succeeded"
	EventLoginFailed       = "user.login_failed"
	EventUserBlocked       = "user.blocked"
	EventSessionRefreshed  = "session.refreshed"
	EventSessionRevoked    = "session.revoked"
	EventPasswordChanged   = "password.changed"
	EventPasswordReset     = "password.reset"
	EventAccountDeleted    = "account.deleted"
	EventRecoveryRequested = "recovery.requested"
)

// Event is a domain event ready for a future broker.
type Event struct {
	Type       string
	UserID     uint64
	OccurredAt time.Time
	Data       map[string]string
}

// EventPublisher isolates the business rules from future messaging.
type EventPublisher interface {
	Publish(ctx context.Context, event Event) error
}

// LogEventPublisher logs events instead of publishing them.
type LogEventPublisher struct {
	logger *slog.Logger
}

func NewLogEventPublisher(logger *slog.Logger) *LogEventPublisher {
	if logger == nil {
		logger = slog.Default()
	}
	return &LogEventPublisher{logger: logger}
}

func (p *LogEventPublisher) Publish(ctx context.Context, event Event) error {
	p.logger.InfoContext(ctx, "domain event", "type", event.Type, "user_id", event.UserID)
	return nil
}
