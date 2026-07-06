package apis_test

import (
	"net/http"
	"testing"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

func mustAuthToken(t testing.TB, app *tests.TestApp, collectionName, email string) string {
	t.Helper()

	record, err := app.FindAuthRecordByEmail(collectionName, email)
	if err != nil {
		t.Fatal(err)
	}

	token, err := record.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}

	return token
}

func mustStaticAuthToken(t testing.TB, app *tests.TestApp, collectionName, email string) string {
	t.Helper()

	record, err := app.FindAuthRecordByEmail(collectionName, email)
	if err != nil {
		t.Fatal(err)
	}

	token, err := record.NewStaticAuthToken(0)
	if err != nil {
		t.Fatal(err)
	}

	return token
}

func TestRecordAuthRefresh(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	superuserAuthToken := mustAuthToken(t, app, core.CollectionNameSuperusers, "test@example.com")
	usersAuthToken := mustAuthToken(t, app, "users", "test@example.com")
	usersStaticAuthToken := mustStaticAuthToken(t, app, "users", "test@example.com")
	clientsUnverifiedAuthToken := mustAuthToken(t, app, "clients", "test2@example.com")
	clientsVerifiedAuthToken := mustAuthToken(t, app, "clients", "test@example.com")

	scenarios := []tests.ApiScenario{
		{
			Name:            "unauthorized",
			Method:          http.MethodPost,
			URL:             "/api/collections/users/auth-refresh",
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "superuser trying to refresh the auth of another auth collection",
			Method: http.MethodPost,
			URL:    "/api/collections/users/auth-refresh",
			Headers: map[string]string{
				"Authorization": superuserAuthToken,
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "auth record + not an auth collection",
			Method: http.MethodPost,
			URL:    "/api/collections/demo1/auth-refresh",
			Headers: map[string]string{
				"Authorization": usersAuthToken,
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "auth record + different auth collection",
			Method: http.MethodPost,
			URL:    "/api/collections/clients/auth-refresh?expand=rel,missing",
			Headers: map[string]string{
				"Authorization": usersAuthToken,
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "auth record + same auth collection as the token",
			Method: http.MethodPost,
			URL:    "/api/collections/users/auth-refresh?expand=rel,missing",
			Headers: map[string]string{
				"Authorization": usersAuthToken,
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"token":`,
				`"record":`,
				`"id":"4q1xlclmfloku33"`,
				`"emailVisibility":false`,
				`"email":"test@example.com"`, // the owner can always view their email address
				`"expand":`,
				`"rel":`,
				`"id":"llvuca81nly1qls"`,
			},
			NotExpectedContent: []string{
				`"missing":`,
				// should return a different token
				usersAuthToken,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordAuthRefreshRequest": 1,
				"OnRecordAuthRequest":        1,
				"OnRecordEnrich":             2,
			},
		},
		{
			Name:   "auth record + same auth collection as the token but static/unrefreshable",
			Method: http.MethodPost,
			URL:    "/api/collections/users/auth-refresh",
			Headers: map[string]string{
				"Authorization": usersStaticAuthToken,
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				// should return the same token
				`"token":"` + usersStaticAuthToken + `"`,
				`"record":`,
				`"id":"4q1xlclmfloku33"`,
				`"emailVisibility":false`,
				`"email":"test@example.com"`, // the owner can always view their email address
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordAuthRefreshRequest": 1,
				"OnRecordAuthRequest":        1,
				"OnRecordEnrich":             1,
			},
		},
		{
			Name:   "unverified auth record in onlyVerified collection",
			Method: http.MethodPost,
			URL:    "/api/collections/clients/auth-refresh",
			Headers: map[string]string{
				"Authorization": clientsUnverifiedAuthToken,
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordAuthRefreshRequest": 1,
			},
		},
		{
			Name:   "verified auth record in onlyVerified collection",
			Method: http.MethodPost,
			URL:    "/api/collections/clients/auth-refresh",
			Headers: map[string]string{
				"Authorization": clientsVerifiedAuthToken,
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"token":`,
				`"record":`,
				`"id":"gk390qegs4y47wn"`,
				`"verified":true`,
				`"email":"test@example.com"`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordAuthRefreshRequest": 1,
				"OnRecordAuthRequest":        1,
				"OnRecordEnrich":             1,
			},
		},
		{
			Name:   "OnRecordAuthRefreshRequest tx body write check",
			Method: http.MethodPost,
			URL:    "/api/collections/users/auth-refresh",
			Headers: map[string]string{
				"Authorization": usersAuthToken,
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.OnRecordAuthRefreshRequest().BindFunc(func(e *core.RecordAuthRefreshRequestEvent) error {
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
			ExpectedEvents:  map[string]int{"OnRecordAuthRefreshRequest": 1},
			ExpectedContent: []string{"TX_ERROR"},
		},

		// rate limit checks
		// -----------------------------------------------------------
		{
			Name:   "RateLimit rule - users:authRefresh",
			Method: http.MethodPost,
			URL:    "/api/collections/users/auth-refresh",
			Headers: map[string]string{
				"Authorization": usersAuthToken,
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().RateLimits.Enabled = true
				app.Settings().RateLimits.Rules = []core.RateLimitRule{
					{MaxRequests: 100, Label: "abc"},
					{MaxRequests: 100, Label: "*:authRefresh"},
					{MaxRequests: 0, Label: "users:authRefresh"},
				}
			},
			ExpectedStatus:  429,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "RateLimit rule - *:authRefresh",
			Method: http.MethodPost,
			URL:    "/api/collections/users/auth-refresh",
			Headers: map[string]string{
				"Authorization": usersAuthToken,
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().RateLimits.Enabled = true
				app.Settings().RateLimits.Rules = []core.RateLimitRule{
					{MaxRequests: 100, Label: "abc"},
					{MaxRequests: 0, Label: "*:authRefresh"},
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
