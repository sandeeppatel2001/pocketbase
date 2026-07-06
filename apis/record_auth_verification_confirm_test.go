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

type tokenBodyReader struct {
	token  *string
	reader *strings.Reader
}

func (r *tokenBodyReader) Read(p []byte) (int, error) {
	if r.reader == nil {
		r.reader = strings.NewReader(`{"token":"` + *r.token + `"}`)
	}

	return r.reader.Read(p)
}

func newTokenBodyReader(token *string) io.Reader {
	return &tokenBodyReader{token: token}
}

func setVerificationToken(t testing.TB, record *core.Record) string {
	t.Helper()

	token, err := record.NewVerificationToken()
	if err != nil {
		t.Fatal(err)
	}

	return token
}

func setPasswordResetToken(t testing.TB, record *core.Record) string {
	t.Helper()

	token, err := record.NewPasswordResetToken()
	if err != nil {
		t.Fatal(err)
	}

	return token
}

func setExpiredVerificationToken(t testing.TB, record *core.Record) string {
	t.Helper()

	token, err := security.NewJWT(jwt.MapClaims{
		core.TokenClaimType:         core.TokenTypeVerification,
		core.TokenClaimId:           record.Id,
		core.TokenClaimCollectionId: record.Collection().Id,
		core.TokenClaimEmail:        record.Email(),
	}, record.TokenKey()+record.Collection().VerificationToken.Secret, -time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	return token
}

func TestRecordConfirmVerification(t *testing.T) {
	t.Parallel()

	var expiredToken string
	var nonVerificationToken string
	var usersToken string
	var verifiedToken string
	var noLoginToken string

	scenarios := []tests.ApiScenario{
		{
			Name:           "empty data",
			Method:         http.MethodPost,
			URL:            "/api/collections/users/confirm-verification",
			Body:           strings.NewReader(``),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"token":{"code":"validation_required"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:            "invalid data format",
			Method:          http.MethodPost,
			URL:             "/api/collections/users/confirm-verification",
			Body:            strings.NewReader(`{"password`),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "expired token",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-verification",
			Body: newTokenBodyReader(&expiredToken),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"token":{"code":"validation_invalid_token"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				user, err := app.FindAuthRecordByEmail("users", "test@example.com")
				if err != nil {
					t.Fatal(err)
				}

				expiredToken = setExpiredVerificationToken(t, user)
			},
		},
		{
			Name:   "non-verification token",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-verification",
			Body: newTokenBodyReader(&nonVerificationToken),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"token":{"code":"validation_invalid_token"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				user, err := app.FindAuthRecordByEmail("users", "test@example.com")
				if err != nil {
					t.Fatal(err)
				}

				nonVerificationToken = setPasswordResetToken(t, user)
			},
		},
		{
			Name:   "non auth collection",
			Method: http.MethodPost,
			URL:    "/api/collections/demo1/confirm-verification?expand=rel,missing",
			Body: newTokenBodyReader(&usersToken),
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				user, err := app.FindAuthRecordByEmail("users", "test@example.com")
				if err != nil {
					t.Fatal(err)
				}

				usersToken = setVerificationToken(t, user)
			},
		},
		{
			Name:   "different auth collection",
			Method: http.MethodPost,
			URL:    "/api/collections/clients/confirm-verification?expand=rel,missing",
			Body: newTokenBodyReader(&usersToken),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{"token":{"code":"validation_token_collection_mismatch"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				user, err := app.FindAuthRecordByEmail("users", "test@example.com")
				if err != nil {
					t.Fatal(err)
				}

				usersToken = setVerificationToken(t, user)
			},
		},
		{
			Name:   "valid token",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-verification",
			Body: newTokenBodyReader(&usersToken),
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                                  0,
				"OnRecordConfirmVerificationRequest": 1,
				"OnModelUpdate":                      1,
				"OnModelValidate":                    1,
				"OnModelUpdateExecute":               1,
				"OnModelAfterUpdateSuccess":          1,
				"OnRecordUpdate":                     1,
				"OnRecordValidate":                   1,
				"OnRecordUpdateExecute":              1,
				"OnRecordAfterUpdateSuccess":         1,
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

				usersToken = setVerificationToken(t, user)

				if user.Verified() {
					t.Fatal("Expected the user to be unverified before the confirmation")
				}

				// ensure that there is at least one pre-existing OAuth2 link
				externalAuths, err := app.FindAllExternalAuthsByRecord(user)
				if err != nil {
					t.Fatal(err)
				}
				if len(externalAuths) == 0 {
					t.Fatal("Expected at least one external auths")
				}
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				user, err := app.FindAuthRecordByEmail("users", "test@example.com")
				if err != nil {
					t.Fatal(err)
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
			Name:   "valid token (disabled password auth)",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-verification",
			Body: strings.NewReader(`{
				"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjRxMXhsY2xtZmxva3UzMyIsImV4cCI6MjUyNDYwNDQ2MSwidHlwZSI6InZlcmlmaWNhdGlvbiIsImNvbGxlY3Rpb25JZCI6Il9wYl91c2Vyc19hdXRoXyIsImVtYWlsIjoidGVzdEBleGFtcGxlLmNvbSJ9.SetHpu2H-x-q4TIUz-xiQjwi7MNwLCLvSs4O0hUSp0E"
			}`),
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                                  0,
				"OnRecordConfirmVerificationRequest": 1,
				"OnModelUpdate":                      1,
				"OnModelValidate":                    1,
				"OnModelUpdateExecute":               1,
				"OnModelAfterUpdateSuccess":          1,
				"OnRecordUpdate":                     1,
				"OnRecordValidate":                   1,
				"OnRecordUpdateExecute":              1,
				"OnRecordAfterUpdateSuccess":         1,
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

				usersToken = setVerificationToken(t, user)

				user.Collection().PasswordAuth.Enabled = false
				if err = app.Save(user.Collection()); err != nil {
					t.Fatal(err)
				}

				if user.Verified() {
					t.Fatal("Expected the user to be unverified before the confirmation")
				}

				if !user.ValidatePassword("1234567890") {
					t.Fatal("Expected password to be valid")
				}

				// ensure that there is at least one pre-existing OAuth2 link
				externalAuths, err := app.FindAllExternalAuthsByRecord(user)
				if err != nil {
					t.Fatal(err)
				}
				if len(externalAuths) == 0 {
					t.Fatal("Expected at least one external auths")
				}
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				user, err := app.FindAuthRecordByEmail("users", "test@example.com")
				if err != nil {
					t.Fatal(err)
				}

				if !user.Verified() {
					t.Fatalf("Expected the user to be verified after the confirmation")
				}

				if user.ValidatePassword("1234567890") {
					t.Fatal("Expected the user password to be reset")
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
			Name:   "valid token (already verified)",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-verification",
			Body: newTokenBodyReader(&verifiedToken),
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                                  0,
				"OnRecordConfirmVerificationRequest": 1,
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				user, err := app.FindAuthRecordByEmail("users", "test2@example.com")
				if err != nil {
					t.Fatal(err)
				}

				verifiedToken = setVerificationToken(t, user)
			},
		},
		{
			Name:   "valid verification token from a collection without allowed login",
			Method: http.MethodPost,
			URL:    "/api/collections/nologin/confirm-verification",
			Body: newTokenBodyReader(&noLoginToken),
			ExpectedStatus:  204,
			ExpectedContent: []string{},
			ExpectedEvents: map[string]int{
				"*":                                  0,
				"OnRecordConfirmVerificationRequest": 1,
				"OnModelUpdate":                      1,
				"OnModelValidate":                    1,
				"OnModelUpdateExecute":               1,
				"OnModelAfterUpdateSuccess":          1,
				"OnRecordUpdate":                     1,
				"OnRecordValidate":                   1,
				"OnRecordUpdateExecute":              1,
				"OnRecordAfterUpdateSuccess":         1,
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				user, err := app.FindAuthRecordByEmail("nologin", "test@example.com")
				if err != nil {
					t.Fatal(err)
				}

				noLoginToken = setVerificationToken(t, user)
			},
		},
		{
			Name:   "OnRecordConfirmVerificationRequest tx body write check",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-verification",
			Body: newTokenBodyReader(&usersToken),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				user, err := app.FindAuthRecordByEmail("users", "test@example.com")
				if err != nil {
					t.Fatal(err)
				}

				usersToken = setVerificationToken(t, user)

				app.OnRecordConfirmVerificationRequest().BindFunc(func(e *core.RecordConfirmVerificationRequestEvent) error {
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
			ExpectedEvents:  map[string]int{"OnRecordConfirmVerificationRequest": 1},
			ExpectedContent: []string{"TX_ERROR"},
		},

		// rate limit checks
		// -----------------------------------------------------------
		{
			Name:   "RateLimit rule - nologin:confirmVerification",
			Method: http.MethodPost,
			URL:    "/api/collections/nologin/confirm-verification",
			Body: newTokenBodyReader(&noLoginToken),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				user, err := app.FindAuthRecordByEmail("nologin", "test@example.com")
				if err != nil {
					t.Fatal(err)
				}

				noLoginToken = setVerificationToken(t, user)

				app.Settings().RateLimits.Enabled = true
				app.Settings().RateLimits.Rules = []core.RateLimitRule{
					{MaxRequests: 100, Label: "abc"},
					{MaxRequests: 100, Label: "*:confirmVerification"},
					{MaxRequests: 0, Label: "nologin:confirmVerification"},
				}
			},
			ExpectedStatus:  429,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "RateLimit rule - *:confirmVerification",
			Method: http.MethodPost,
			URL:    "/api/collections/nologin/confirm-verification",
			Body: newTokenBodyReader(&noLoginToken),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				user, err := app.FindAuthRecordByEmail("nologin", "test@example.com")
				if err != nil {
					t.Fatal(err)
				}

				noLoginToken = setVerificationToken(t, user)

				app.Settings().RateLimits.Enabled = true
				app.Settings().RateLimits.Rules = []core.RateLimitRule{
					{MaxRequests: 100, Label: "abc"},
					{MaxRequests: 0, Label: "*:confirmVerification"},
				}
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
