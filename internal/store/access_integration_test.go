package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"go-base/internal/auth"
	"go-base/internal/domain"
)

func TestSuspensionFailureNeverExposesPartialAccessState(t *testing.T) {
	database := bootstrapDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	actor := domain.User{ID: "mgr-1", TenantID: "demo", Role: domain.RoleManager}
	service := auth.AccessService{
		Repo: AccessRepository{DB: database},
		Now:  func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}

	for _, testCase := range []struct {
		name               string
		triggerTable       string
		triggerColumn      string
		blockedQuery       string
		wantDisabledDuring bool
		wantRevokedDuring  bool
	}{
		{name: "session revocation fails", triggerTable: "sessions", triggerColumn: "revoked_at", blockedQuery: "update sessions"},
		{name: "user disable fails", triggerTable: "users", triggerColumn: "disabled", blockedQuery: "update users"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			resetOperatorAccess(t, database)
			lockKey := int64(8_401_000 + len(testCase.name))
			installAccessFailureTrigger(t, database, testCase.triggerTable, testCase.triggerColumn, lockKey)

			lockConnection, err := database.Pool.Acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer lockConnection.Release()
			if _, err := lockConnection.Exec(ctx, `SELECT pg_advisory_lock($1)`, lockKey); err != nil {
				t.Fatal(err)
			}

			result := make(chan error, 1)
			go func() {
				_, err := service.Suspend(context.Background(), actor, "op-1")
				result <- err
			}()
			waitForAccessQuery(t, database, testCase.blockedQuery)
			disabled, revoked := operatorAccessState(t, database)
			if disabled != testCase.wantDisabledDuring || revoked != testCase.wantRevokedDuring {
				t.Errorf("partial access state became visible: disabled=%v revoked=%v", disabled, revoked)
			}

			if _, err := lockConnection.Exec(ctx, `SELECT pg_advisory_unlock($1)`, lockKey); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("Suspend() succeeded despite injected database failure")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Suspend() remained blocked after releasing failure trigger")
			}
			disabled, revoked = operatorAccessState(t, database)
			if disabled || revoked {
				t.Fatalf("failed suspension left state behind: disabled=%v revoked=%v", disabled, revoked)
			}
		})
	}

	resetOperatorAccess(t, database)
	if _, err := service.Suspend(ctx, actor, "op-1"); err != nil {
		t.Fatalf("successful suspension: %v", err)
	}
	disabled, revoked := operatorAccessState(t, database)
	if !disabled || !revoked {
		t.Fatalf("successful suspension state: disabled=%v revoked=%v", disabled, revoked)
	}
}

func resetOperatorAccess(t *testing.T, database *Database) {
	t.Helper()
	if _, err := database.Pool.Exec(context.Background(), `
		DROP TRIGGER IF EXISTS fail_access_change ON users;
		DROP TRIGGER IF EXISTS fail_access_change ON sessions;
		DROP FUNCTION IF EXISTS fail_access_change();
		UPDATE users SET disabled=false WHERE tenant_id='demo' AND id='op-1';
		DELETE FROM sessions WHERE user_id='op-1';
		INSERT INTO sessions(id,user_id,tenant_id,token_digest,expires_at)
		VALUES('suspend-session','op-1','demo','suspend-token',now()+interval '1 hour');
	`); err != nil {
		t.Fatal(err)
	}
}

func installAccessFailureTrigger(t *testing.T, database *Database, table, column string, lockKey int64) {
	t.Helper()
	statement := fmt.Sprintf(`
		CREATE OR REPLACE FUNCTION fail_access_change() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM pg_advisory_xact_lock(%d);
			RAISE EXCEPTION 'injected access write failure';
		END $$;
		CREATE TRIGGER fail_access_change BEFORE UPDATE OF %s ON %s
		FOR EACH STATEMENT EXECUTE FUNCTION fail_access_change();`, lockKey, column, table)
	if _, err := database.Pool.Exec(context.Background(), statement); err != nil {
		t.Fatal(err)
	}
}

func waitForAccessQuery(t *testing.T, database *Database, queryFragment string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var found bool
		err := database.Pool.QueryRow(context.Background(), `
			SELECT EXISTS(
				SELECT 1 FROM pg_stat_activity
				WHERE datname=current_database()
				AND wait_event_type='Lock'
				AND lower(query) LIKE $1
			)`, "%"+strings.ToLower(queryFragment)+"%").Scan(&found)
		if err != nil {
			t.Fatal(err)
		}
		if found {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("did not observe blocked %s statement", queryFragment)
}

func operatorAccessState(t *testing.T, database *Database) (bool, bool) {
	t.Helper()
	var disabled, revoked bool
	if err := database.Pool.QueryRow(context.Background(), `
		SELECT u.disabled,(s.revoked_at IS NOT NULL)
		FROM users u JOIN sessions s ON s.user_id=u.id
		WHERE u.tenant_id='demo' AND u.id='op-1' AND s.id='suspend-session'`).Scan(&disabled, &revoked); err != nil {
		t.Fatal(err)
	}
	return disabled, revoked
}
