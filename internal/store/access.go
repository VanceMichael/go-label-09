package store

import (
	"context"
	"fmt"
	"time"

	"go-base/internal/domain"
)

type AccessRepository struct {
	DB *Database
}

func (repository AccessRepository) DisableUser(ctx context.Context, tenant, user string, at time.Time) error {
	if repository.DB == nil || repository.DB.Pool == nil {
		return fmt.Errorf("%w: access database", domain.ErrInvalid)
	}
	if tenant == "" || user == "" || at.IsZero() {
		return fmt.Errorf("%w: user suspension", domain.ErrInvalid)
	}
	tag, err := repository.DB.Pool.Exec(ctx, `
		UPDATE users
		SET disabled=true
		WHERE tenant_id=$1 AND id=$2 AND disabled=false`, tenant, user)
	if err != nil {
		return fmt.Errorf("disable user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (repository AccessRepository) RevokeUserSessions(ctx context.Context, tenant, user string, at time.Time) error {
	if repository.DB == nil || repository.DB.Pool == nil {
		return fmt.Errorf("%w: access database", domain.ErrInvalid)
	}
	if tenant == "" || user == "" || at.IsZero() {
		return fmt.Errorf("%w: session revocation", domain.ErrInvalid)
	}
	if _, err := repository.DB.Pool.Exec(ctx, `
		UPDATE sessions
		SET revoked_at=$3
		WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NULL`, tenant, user, at); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}
	return nil
}
