package service

import (
	"context"
	"log/slog"
)

// NotificationService isolates the business rules from future providers.
type NotificationService interface {
	SendPasswordRecoveryCode(ctx context.Context, email, code string) error
	DeliveryEnabled() bool
}

// LogNotificationService is a study implementation that logs instead of
// delivering. It reports delivery as disabled, so codes are returned inline.
type LogNotificationService struct {
	logger *slog.Logger
}

func NewLogNotificationService(logger *slog.Logger) *LogNotificationService {
	if logger == nil {
		logger = slog.Default()
	}
	return &LogNotificationService{logger: logger}
}

func (s *LogNotificationService) DeliveryEnabled() bool {
	return false
}

func (s *LogNotificationService) SendPasswordRecoveryCode(ctx context.Context, email, code string) error {
	// The code is not logged; it is returned inline while delivery is disabled.
	s.logger.InfoContext(ctx, "password recovery notification skipped", "email", email)
	return nil
}
