package apis_test

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
	"github.com/pocketbase/pocketbase/tools/security"
)

type lazyStringReader struct {
	fn   func() string
	data []byte
}

func (r *lazyStringReader) Read(p []byte) (int, error) {
	if r.data == nil {
		r.data = []byte(r.fn())
	}

	if len(r.data) == 0 {
		return 0, io.EOF
	}

	n := copy(p, r.data)
	r.data = r.data[n:]

	if len(r.data) == 0 {
		return n, io.EOF
	}

	return n, nil
}

func newEmailChangeConfirmToken(t testing.TB, app *tests.TestApp, collectionName, email, newEmail string, duration time.Duration) string {
	t.Helper()

	record, err := app.FindAuthRecordByEmail(collectionName, email)
	if err != nil {
		t.Fatal(err)
	}

	token, err := security.NewJWT(jwt.MapClaims{
		core.TokenClaimType:         core.TokenTypeEmailChange,
		core.TokenClaimId:           record.Id,
		core.TokenClaimCollectionId: record.Collection().Id,
		core.TokenClaimEmail:        record.Email(),
		core.TokenClaimNewEmail:     newEmail,
	}, record.TokenKey()+record.Collection().EmailChangeToken.Secret, duration)
	if err != nil {
		t.Fatal(err)
	}

	return token
}

func newEmailChangeConfirmBody(token *string, password string) io.Reader {
	return &lazyStringReader{fn: func() string {
		return `{"token":"` + *token + `","password":"` + password + `"}`
	}}
}

func TestRecordConfirmEmailChange(t *testing.T) {
	t.Parallel()

	var expiredToken string
	var validToken string

	scenarios := []tests.ApiScenario{
		{
			Name:            "not an auth collection",
			Method:          http.MethodPost,
			URL:             "/api/collections/demo1/confirm-email-change",
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:           "empty data",
			Method:         http.MethodPost,
			URL:            "/api/collections/users/confirm-email-change",
			Body:           strings.NewReader(``),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":`,
				`"token":{"code":"validation_required"`,
				`"password":{"code":"validation_required"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:            "invalid data",
			Method:          http.MethodPost,
			URL:             "/api/collections/users/confirm-email-change",
			Body:            strings.NewReader(`{"token`),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "expired token and correct password",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-email-change",
			Body: newEmailChangeConfirmBody(&expiredToken, "1234567890"),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				expiredToken = newEmailChangeConfirmToken(t, app, "users", "test@example.com", "change@example.com", -time.Hour)
			},
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"token":{`,
				`"code":"validation_invalid_token"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "non-email change token",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-email-change",
			Body: strings.NewReader(`{
				"token":"<redacted-test-token>",
				"password":"1234567890"
			}`),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"token":{`,
				`"code":"validation_invalid_token_payload"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "valid token and incorrect password",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-email-change",
			Body: newEmailChangeConfirmBody(&validToken, "1234567891"),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				validToken = newEmailChangeConfirmToken(t, app, "users", "test@example.com", "change@example.com", time.Hour)
			},
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"password":{`,
				`"code":"validation_invalid_password"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "valid token and correct password",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-email-change",
			Body: newEmailChangeConfirmBody(&validToken, "1234567890"),
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                                 0,
				"OnRecordConfirmEmailChangeRequest": 1,
				"OnModelUpdate":                     1,
				"OnModelUpdateExecute":              1,
				"OnModelAfterUpdateSuccess":         1,
				"OnModelValidate":                   1,
				"OnRecordUpdate":                    1,
				"OnRecordUpdateExecute":             1,
				"OnRecordAfterUpdateSuccess":        1,
				"OnRecordValidate":                  1,
				// unverified->verified external auths removal
				"OnModelDelete":              2,
				"OnModelDeleteExecute":       2,
				"OnModelAfterDeleteSuccess":  2,
				"OnRecordDelete":             2,
				"OnRecordDeleteExecute":      2,
				"OnRecordAfterDeleteSuccess": 2,
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				user, err := app.FindAuthRecordByEmail("users", "test@example.com")
				if err != nil {
					t.Fatal(err)
				}

				if user.Verified() {
					t.Fatalf("Expected the user to be unverified before the confirmation")
				}

				// ensure that there is at least one pre-existing OAuth2 link
				externalAuths, err := app.FindAllExternalAuthsByRecord(user)
				if err != nil {
					t.Fatal(err)
				}
				if len(externalAuths) == 0 {
					t.Fatal("Expected at least one external auths")
				}

				validToken = newEmailChangeConfirmToken(t, app, "users", "test@example.com", "change@example.com", time.Hour)
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				user, err := app.FindAuthRecordByEmail("users", "change@example.com")
				if err != nil {
					t.Fatalf("Expected to find user with email %q, got error: %v", "change@example.com", err)
				}

				if !user.Verified() {
					t.Fatalf("Expected the user to be verified after the confirmation")
				}

				// ensure that all pre-existing OAuth2 links are cleared
				externalAuths, err := app.FindAllExternalAuthsByRecord(user)
				if err != nil {
					t.Fatal(err)
				}
				if len(externalAuths) > 0 {
					t.Fatalf("Expected all external auths to be cleared, found %d", len(externalAuths))
				}
			},
		},
		{
			Name:   "valid token in different auth collection",
			Method: http.MethodPost,
			URL:    "/api/collections/clients/confirm-email-change",
			Body: newEmailChangeConfirmBody(&validToken, "1234567890"),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				validToken = newEmailChangeConfirmToken(t, app, "users", "test@example.com", "change@example.com", time.Hour)
			},
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"token":{"code":"validation_token_collection_mismatch"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "OnRecordConfirmEmailChangeRequest tx body write check",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-email-change",
			Body: newEmailChangeConfirmBody(&validToken, "1234567890"),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				validToken = newEmailChangeConfirmToken(t, app, "users", "test@example.com", "change@example.com", time.Hour)

				app.OnRecordConfirmEmailChangeRequest().BindFunc(func(e *core.RecordConfirmEmailChangeRequestEvent) error {
					original := e.App
					return e.App.RunInTransaction(func(txApp core.App) error {
						e.App = txApp
						defer func() { e.App = original }()

						if err := e.Next(); err != nil {
							return err
						}

						return e.BadRequestError("TX_ERROR", nil)
					})
				})
			},
			ExpectedStatus:  400,
			ExpectedEvents:  map[string]int{"OnRecordConfirmEmailChangeRequest": 1},
			ExpectedContent: []string{"TX_ERROR"},
		},

		// rate limit checks
		// -----------------------------------------------------------
		{
			Name:   "RateLimit rule - users:confirmEmailChange",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-email-change",
			Body: newEmailChangeConfirmBody(&validToken, "1234567890"),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().RateLimits.Enabled = true
				app.Settings().RateLimits.Rules = []core.RateLimitRule{
					{MaxRequests: 100, Label: "abc"},
					{MaxRequests: 100, Label: "*:confirmEmailChange"},
					{MaxRequests: 0, Label: "users:confirmEmailChange"},
				}
				validToken = newEmailChangeConfirmToken(t, app, "users", "test@example.com", "change@example.com", time.Hour)
			},
			ExpectedStatus:  429,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "RateLimit rule - *:confirmEmailChange",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-email-change",
			Body: newEmailChangeConfirmBody(&validToken, "1234567890"),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().RateLimits.Enabled = true
				app.Settings().RateLimits.Rules = []core.RateLimitRule{
					{MaxRequests: 100, Label: "abc"},
					{MaxRequests: 0, Label: "*:confirmEmailChange"},
				}
				validToken = newEmailChangeConfirmToken(t, app, "users", "test@example.com", "change@example.com", time.Hour)
			},
			ExpectedStatus:  429,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}
