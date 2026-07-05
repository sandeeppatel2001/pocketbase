package apis_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
	"github.com/pocketbase/pocketbase/tools/security"
)

func TestRecordConfirmVerification(t *testing.T) {
	t.Parallel()

	// generate dynamic test tokens to avoid hardcoded JWTs in the source
	tokenApp, tokenAppErr := tests.NewTestApp()
	if tokenAppErr != nil {
		t.Fatal(tokenAppErr)
	}
	defer tokenApp.Cleanup()

	tokenUser, tokenErr := tokenApp.FindAuthRecordByEmail("users", "test@example.com")
	if tokenErr != nil {
		t.Fatal(tokenErr)
	}

	validVerificationToken, tokenErr := tokenUser.NewVerificationToken()
	if tokenErr != nil {
		t.Fatal(tokenErr)
	}

	// generate expired verification token
	signingKey := tokenUser.TokenKey() + tokenUser.Collection().VerificationToken.Secret
	expiredVerificationToken, tokenErr := security.NewJWT(jwt.MapClaims{
		core.TokenClaimType:         core.TokenTypeVerification,
		core.TokenClaimId:           tokenUser.Id,
		core.TokenClaimCollectionId: tokenUser.Collection().Id,
		core.TokenClaimEmail:        tokenUser.Email(),
	}, signingKey, -time.Hour)
	if tokenErr != nil {
		t.Fatal(tokenErr)
	}

	// generate a non-verification token (password reset)
	nonVerificationToken, tokenErr := tokenUser.NewPasswordResetToken()
	if tokenErr != nil {
		t.Fatal(tokenErr)
	}

	// generate a verification token for an already verified user
	tokenUserVerified, tokenErr := tokenApp.FindAuthRecordByEmail("users", "test2@example.com")
	if tokenErr != nil {
		t.Fatal(tokenErr)
	}

	validVerificationTokenVerified, tokenErr := tokenUserVerified.NewVerificationToken()
	if tokenErr != nil {
		t.Fatal(tokenErr)
	}

	// generate a verification token for the nologin collection
	tokenUserNoLogin, tokenErr := tokenApp.FindAuthRecordByEmail("nologin", "test@example.com")
	if tokenErr != nil {
		t.Fatal(tokenErr)
	}

	validVerificationTokenNoLogin, tokenErr := tokenUserNoLogin.NewVerificationToken()
	if tokenErr != nil {
		t.Fatal(tokenErr)
	}

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
			Body: strings.NewReader(fmt.Sprintf(`{
				"token":"%s"
			}`, expiredVerificationToken)),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"token":{"code":"validation_invalid_token"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "non-verification token",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-verification",
			Body: strings.NewReader(fmt.Sprintf(`{
				"token":"%s"
			}`, nonVerificationToken)),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"token":{"code":"validation_invalid_token"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "non auth collection",
			Method: http.MethodPost,
			URL:    "/api/collections/demo1/confirm-verification?expand=rel,missing",
			Body: strings.NewReader(fmt.Sprintf(`{
				"token":"%s"
			}`, validVerificationToken)),
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "different auth collection",
			Method: http.MethodPost,
			URL:    "/api/collections/clients/confirm-verification?expand=rel,missing",
			Body: strings.NewReader(fmt.Sprintf(`{
				"token":"%s"
			}`, validVerificationToken)),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{"token":{"code":"validation_token_collection_mismatch"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "valid token",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-verification",
			Body: strings.NewReader(fmt.Sprintf(`{
				"token":"%s"
			}`, validVerificationToken)),
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
			Body: strings.NewReader(fmt.Sprintf(`{
				"token":"%s"
			}`, validVerificationToken)),
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
			Body: strings.NewReader(fmt.Sprintf(`{
				"token":"%s"
			}`, validVerificationTokenVerified)),
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                                  0,
				"OnRecordConfirmVerificationRequest": 1,
			},
		},
		{
			Name:   "valid verification token from a collection without allowed login",
			Method: http.MethodPost,
			URL:    "/api/collections/nologin/confirm-verification",
			Body: strings.NewReader(fmt.Sprintf(`{
				"token":"%s"
			}`, validVerificationTokenNoLogin)),
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
		},
		{
			Name:   "OnRecordConfirmVerificationRequest tx body write check",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-verification",
			Body: strings.NewReader(fmt.Sprintf(`{
				"token":"%s"
			}`, validVerificationToken)),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
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
			Body: strings.NewReader(fmt.Sprintf(`{
				"token":"%s"
			}`, validVerificationTokenNoLogin)),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
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
			Body: strings.NewReader(fmt.Sprintf(`{
				"token":"%s"
			}`, validVerificationTokenNoLogin)),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
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
