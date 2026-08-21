package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go-base/internal/domain"
)

type AccessRepository interface {
	DisableUser(context.Context, string, string, time.Time) error
	RevokeUserSessions(context.Context, string, string, time.Time) error
}

type AccessService struct {
	Repo AccessRepository
	Now  func() time.Time
}

type Suspension struct {
	TenantID string
	UserID   string
	ActorID  string
	At       time.Time
}

func (service AccessService) Suspend(ctx context.Context, actor domain.User, target string) (Suspension, error) {
	if service.Repo == nil {
		return Suspension{}, fmt.Errorf("%w: access repository", domain.ErrInvalid)
	}
	if err := RequireRole(actor, domain.RoleManager); err != nil {
		return Suspension{}, err
	}
	target = strings.TrimSpace(target)
	if actor.TenantID == "" || actor.ID == "" || target == "" {
		return Suspension{}, fmt.Errorf("%w: access suspension identity", domain.ErrInvalid)
	}
	if actor.ID == target {
		return Suspension{}, errors.Join(domain.ErrConflict, fmt.Errorf("manager cannot suspend own access"))
	}
	at := time.Now().UTC()
	if service.Now != nil {
		if value := service.Now(); !value.IsZero() {
			at = value.UTC()
		}
	}
	result := Suspension{TenantID: actor.TenantID, UserID: target, ActorID: actor.ID, At: at}
	if err := service.Repo.DisableUser(ctx, result.TenantID, result.UserID, result.At); err != nil {
		return Suspension{}, fmt.Errorf("disable user access: %w", err)
	}
	if err := service.Repo.RevokeUserSessions(ctx, result.TenantID, result.UserID, result.At); err != nil {
		return Suspension{}, fmt.Errorf("revoke user sessions: %w", err)
	}
	return result, nil
}
