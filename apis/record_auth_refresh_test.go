package apis_test

import (
	"net/http"
	"testing"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

func TestRecordAuthRefresh(t *testing.T) {
	t.Parallel()

	// generate dynamic test tokens to avoid hardcoded JWTs in the source
	tokenApp, tokenAppErr := tests.NewTestApp()
	if tokenAppErr != nil {
		t.Fatal(tokenAppErr)
	}
	defer tokenApp.Cleanup()

	superuser, err := tokenApp.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	superuserToken, err := superuser.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}

	user1, err := tokenApp.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	user1Token, err := user1.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	user1StaticToken, err := user1.NewStaticAuthToken(0)
	if err != nil {
		t.Fatal(err)
	}

	clientUnverified, err := tokenApp.FindRecordById("clients", "o1y0dd0spd786md")
	if err != nil {
		t.Fatal(err)
	}
	clientUnverifiedToken, err := clientUnverified.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}

	clientVerified, err := tokenApp.FindRecordById("clients", "gk390qegs4y47wn")
	if err != nil {
		t.Fatal(err)
	}
	clientVerifiedToken, err := clientVerified.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}

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
				"Authorization": superuserToken,
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
				"Authorization": user1Token,
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
				"Authorization": user1Token,
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
				"Authorization": user1Token,
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
				user1Token,
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
				"Authorization": user1StaticToken,
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				// should return the same token
				`"token":"` + user1StaticToken + `"`,
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
				"Authorization": clientUnverifiedToken,
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
				"Authorization": clientVerifiedToken,
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
				"Authorization": user1Token,
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
				"Authorization": user1Token,
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
				"Authorization": user1Token,
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
