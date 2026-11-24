package service

import (
	"context"
	"time"

	"github.com/fabricio948/system_login/internal/model"
	"github.com/fabricio948/system_login/internal/repository"
)

func profileFromUser(user *model.User) *Profile {
	return &Profile{
		ID:        user.ID,
		Name:      user.Name,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
	}
}

func blockedError(user *model.User, now time.Time) *BlockedError {
	blocked := &BlockedError{
		Admin:  user.IsAdminBlocked,
		Reason: user.BlockReason,
	}
	if blocked.Admin || user.BlockedUntil == nil {
		return blocked
	}

	until := *user.BlockedUntil
	blocked.Until = &until
	if remaining := until.Sub(now); remaining > 0 {
		blocked.Remaining = remaining
	}
	return blocked
}

// clearStaleBlock resets expired temporary blocks and metadata left behind by
// an administrative reactivation, so the failure counter starts from zero.
func clearStaleBlock(ctx context.Context, users repository.UserRepository, user *model.User, now time.Time) error {
	if user.IsAdminBlocked {
		return nil
	}

	expiredTemporary := user.HasExpiredTemporaryBlock(now)
	staleAdmin := user.BlockType == model.BlockTypeAdmin
	if !expiredTemporary && !staleAdmin {
		return nil
	}

	if err := users.ClearBlock(ctx, user.ID); err != nil {
		return err
	}

	user.BlockType = ""
	user.BlockReason = ""
	user.BlockedAt = nil
	user.BlockedUntil = nil
	user.FailedLoginAttempts = 0
	return nil
}

func loadAccessibleUser(ctx context.Context, users repository.UserRepository, userID uint64, now time.Time) (*model.User, error) {
	user, err := users.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if err := clearStaleBlock(ctx, users, user, now); err != nil {
		return nil, err
	}
	if !user.IsActive {
		return nil, model.ErrUserInactive
	}
	if user.IsBlocked(now) {
		return nil, blockedError(user, now)
	}
	return user, nil
}

// publishEvent is best effort: a messaging failure must not roll back a
// business operation that already succeeded.
func publishEvent(ctx context.Context, publisher EventPublisher, clock Clock, eventType string, userID uint64, data map[string]string) {
	if publisher == nil {
		return
	}
	_ = publisher.Publish(ctx, Event{
		Type:       eventType,
		UserID:     userID,
		OccurredAt: clock.Now(),
		Data:       data,
	})
}
