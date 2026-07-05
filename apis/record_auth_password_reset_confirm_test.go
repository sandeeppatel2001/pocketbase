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

func TestRecordConfirmPasswordReset(t *testing.T) {
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

	validPasswordResetToken, tokenErr := tokenUser.NewPasswordResetToken()
	if tokenErr != nil {
		t.Fatal(tokenErr)
	}

	// generate expired password reset token
	signingKey := tokenUser.TokenKey() + tokenUser.Collection().PasswordResetToken.Secret
	expiredPasswordResetToken, tokenErr := security.NewJWT(jwt.MapClaims{
		core.TokenClaimType:         core.TokenTypePasswordReset,
		core.TokenClaimId:           tokenUser.Id,
		core.TokenClaimCollectionId: tokenUser.Collection().Id,
		core.TokenClaimEmail:        tokenUser.Email(),
	}, signingKey, -time.Hour)
	if tokenErr != nil {
		t.Fatal(tokenErr)
	}

	// generate a non-password-reset token
	nonPasswordResetToken, tokenErr := tokenUser.NewVerificationToken()
	if tokenErr != nil {
		t.Fatal(tokenErr)
	}

	scenarios := []tests.ApiScenario{
		{
			Name:           "empty data",
			Method:         http.MethodPost,
			URL:            "/api/collections/users/confirm-password-reset",
			Body:           strings.NewReader(``),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"password":{"code":"validation_required"`,
				`"passwordConfirm":{"code":"validation_required"`,
				`"token":{"code":"validation_required"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:            "invalid data format",
			Method:          http.MethodPost,
			URL:             "/api/collections/users/confirm-password-reset",
			Body:            strings.NewReader(`{"password`),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "expired token and invalid password",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-password-reset",
			Body: strings.NewReader(fmt.Sprintf(`{
				"token":"%s",
				"password":"1234567",
				"passwordConfirm":"7654321"
			}`, expiredPasswordResetToken)),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"token":{"code":"validation_invalid_token"`,
				`"password":{"code":"validation_length_out_of_range"`,
				`"passwordConfirm":{"code":"validation_values_mismatch"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "non-password reset token",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-password-reset",
			Body: strings.NewReader(fmt.Sprintf(`{
				"token":"%s",
				"password":"1234567!",
				"passwordConfirm":"1234567!"
			}`, nonPasswordResetToken)),
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
			URL:    "/api/collections/demo1/confirm-password-reset?expand=rel,missing",
			Body: strings.NewReader(fmt.Sprintf(`{
				"token":"%s",
				"password":"1234567!",
				"passwordConfirm":"1234567!"
			}`, validPasswordResetToken)),
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "different auth collection",
			Method: http.MethodPost,
			URL:    "/api/collections/clients/confirm-password-reset?expand=rel,missing",
			Body: strings.NewReader(fmt.Sprintf(`{
				"token":"%s",
				"password":"1234567!",
				"passwordConfirm":"1234567!"
			}`, validPasswordResetToken)),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{"token":{"code":"validation_token_collection_mismatch"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "valid token and data (unverified user)",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-password-reset",
			Body: strings.NewReader(fmt.Sprintf(`{
				"token":"%s",
				"password":"1234567!",
				"passwordConfirm":"1234567!"
			}`, validPasswordResetToken)),
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                                   0,
				"OnRecordConfirmPasswordResetRequest": 1,
				"OnModelUpdate":                       1,
				"OnModelUpdateExecute":                1,
				"OnModelAfterUpdateSuccess":           1,
				"OnRecordUpdate":                      1,
				"OnRecordUpdateExecute":               1,
				"OnRecordAfterUpdateSuccess":          1,
				"OnModelValidate":                     1,
				"OnRecordValidate":                    1,
				// ---
				"OnModelDelete":              2, // pre-existing OAuth2 links
				"OnModelDeleteExecute":       2,
				"OnModelAfterDeleteSuccess":  2,
				"OnRecordDelete":             2,
				"OnRecordDeleteExecute":      2,
				"OnRecordAfterDeleteSuccess": 2,
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				user, err := app.FindAuthRecordByEmail("users", "test@example.com")
				if err != nil {
					t.Fatalf("Failed to fetch confirm password user: %v", err)
				}

				if user.Verified() {
					t.Fatal("Expected the user to be unverified")
				}
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				_, err := app.FindAuthRecordByToken(
					validPasswordResetToken,
					core.TokenTypePasswordReset,
				)
				if err == nil {
					t.Fatal("Expected the password reset token to be invalidated")
				}

				user, err := app.FindAuthRecordByEmail("users", "test@example.com")
				if err != nil {
					t.Fatalf("Failed to fetch confirm password user: %v", err)
				}

				if !user.Verified() {
					t.Fatal("Expected the user to be marked as verified")
				}

				if !user.ValidatePassword("1234567!") {
					t.Fatal("Password wasn't changed")
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
			Name:   "valid token and data (unverified user with different email from the one in the token)",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-password-reset",
			Body: strings.NewReader(fmt.Sprintf(`{
				"token":"%s",
				"password":"1234567!",
				"passwordConfirm":"1234567!"
			}`, validPasswordResetToken)),
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                                   0,
				"OnRecordConfirmPasswordResetRequest": 1,
				"OnModelUpdate":                       1,
				"OnModelUpdateExecute":                1,
				"OnModelAfterUpdateSuccess":           1,
				"OnModelValidate":                     1,
				"OnRecordUpdate":                      1,
				"OnRecordUpdateExecute":               1,
				"OnRecordAfterUpdateSuccess":          1,
				"OnRecordValidate":                    1,
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				user, err := app.FindAuthRecordByEmail("users", "test@example.com")
				if err != nil {
					t.Fatalf("Failed to fetch confirm password user: %v", err)
				}

				if user.Verified() {
					t.Fatal("Expected the user to be unverified")
				}

				oldTokenKey := user.TokenKey()

				// manually change the email to check whether the verified state will be updated
				user.SetEmail("test_update@example.com")
				if err = app.Save(user); err != nil {
					t.Fatalf("Failed to update user test email: %v", err)
				}

				// resave with the old token key since the email change above
				// would change it and will make the password token invalid
				user.SetTokenKey(oldTokenKey)
				if err = app.Save(user); err != nil {
					t.Fatalf("Failed to restore original user tokenKey: %v", err)
				}
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				_, err := app.FindAuthRecordByToken(
					validPasswordResetToken,
					core.TokenTypePasswordReset,
				)
				if err == nil {
					t.Fatalf("Expected the password reset token to be invalidated")
				}

				user, err := app.FindAuthRecordByEmail("users", "test_update@example.com")
				if err != nil {
					t.Fatalf("Failed to fetch confirm password user: %v", err)
				}

				if user.Verified() {
					t.Fatal("Expected the user to remain unverified")
				}

				if !user.ValidatePassword("1234567!") {
					t.Fatal("Password wasn't changed")
				}

				// ensure that all pre-existing OAuth2 were NOT deleted
				externalAuths, err := app.FindAllExternalAuthsByRecord(user)
				if err != nil {
					t.Fatal(err)
				}
				if len(externalAuths) != 2 {
					t.Fatalf("Expected 2 external auths, found %d", len(externalAuths))
				}
			},
		},
		{
			Name:   "valid token and data (verified user)",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-password-reset",
			Body: strings.NewReader(fmt.Sprintf(`{
				"token":"%s",
				"password":"1234567!",
				"passwordConfirm":"1234567!"
			}`, validPasswordResetToken)),
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                                   0,
				"OnRecordConfirmPasswordResetRequest": 1,
				"OnModelUpdate":                       1,
				"OnModelUpdateExecute":                1,
				"OnModelAfterUpdateSuccess":           1,
				"OnModelValidate":                     1,
				"OnRecordUpdate":                      1,
				"OnRecordUpdateExecute":               1,
				"OnRecordAfterUpdateSuccess":          1,
				"OnRecordValidate":                    1,
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				user, err := app.FindAuthRecordByEmail("users", "test@example.com")
				if err != nil {
					t.Fatalf("Failed to fetch confirm password user: %v", err)
				}

				oldTokenKey := user.TokenKey()

				// ensure that the user is already verified
				user.SetVerified(true)
				if err := app.Save(user); err != nil {
					t.Fatalf("Failed to update user verified state")
				}

				// resave with the old token key since the verified change above
				// would refresh it and will make the password token invalid
				user.SetTokenKey(oldTokenKey)
				if err = app.Save(user); err != nil {
					t.Fatalf("Failed to restore original user tokenKey: %v", err)
				}
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				_, err := app.FindAuthRecordByToken(
					validPasswordResetToken,
					core.TokenTypePasswordReset,
				)
				if err == nil {
					t.Fatal("Expected the password reset token to be invalidated")
				}

				user, err := app.FindAuthRecordByEmail("users", "test@example.com")
				if err != nil {
					t.Fatalf("Failed to fetch confirm password user: %v", err)
				}

				if !user.Verified() {
					t.Fatal("Expected the user to remain verified")
				}

				if !user.ValidatePassword("1234567!") {
					t.Fatal("Password wasn't changed")
				}
			},
		},
		{
			Name:   "OnRecordConfirmPasswordResetRequest tx body write check",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-password-reset",
			Body: strings.NewReader(fmt.Sprintf(`{
				"token":"%s",
				"password":"1234567!",
				"passwordConfirm":"1234567!"
			}`, validPasswordResetToken)),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.OnRecordConfirmPasswordResetRequest().BindFunc(func(e *core.RecordConfirmPasswordResetRequestEvent) error {
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
			ExpectedEvents:  map[string]int{"OnRecordConfirmPasswordResetRequest": 1},
			ExpectedContent: []string{"TX_ERROR"},
		},

		// rate limit checks
		// -----------------------------------------------------------
		{
			Name:   "RateLimit rule - users:confirmPasswordReset",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-password-reset",
			Body: strings.NewReader(fmt.Sprintf(`{
				"token":"%s",
				"password":"1234567!",
				"passwordConfirm":"1234567!"
			}`, validPasswordResetToken)),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().RateLimits.Enabled = true
				app.Settings().RateLimits.Rules = []core.RateLimitRule{
					{MaxRequests: 100, Label: "abc"},
					{MaxRequests: 100, Label: "*:confirmPasswordReset"},
					{MaxRequests: 0, Label: "users:confirmPasswordReset"},
				}
			},
			ExpectedStatus:  429,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "RateLimit rule - *:confirmPasswordReset",
			Method: http.MethodPost,
			URL:    "/api/collections/users/confirm-password-reset",
			Body: strings.NewReader(fmt.Sprintf(`{
				"token":"%s",
				"password":"1234567!",
				"passwordConfirm":"1234567!"
			}`, validPasswordResetToken)),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().RateLimits.Enabled = true
				app.Settings().RateLimits.Rules = []core.RateLimitRule{
					{MaxRequests: 100, Label: "abc"},
					{MaxRequests: 0, Label: "*:confirmPasswordReset"},
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
