package apis_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
	"github.com/spf13/cast"
)

func TestCronsList(t *testing.T) {
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

	scenarios := []tests.ApiScenario{
		{
			Name:            "unauthorized",
			Method:          http.MethodGet,
			URL:             "/api/crons",
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "authorized as regular user",
			Method: http.MethodGet,
			URL:    "/api/crons",
			Headers: map[string]string{
				"Authorization": user1Token,
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "authorized as superuser (empty list)",
			Method: http.MethodGet,
			URL:    "/api/crons",
			Headers: map[string]string{
				"Authorization": superuserToken,
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Cron().RemoveAll()
			},
			ExpectedStatus:  200,
			ExpectedContent: []string{`[]`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "authorized as superuser",
			Method: http.MethodGet,
			URL:    "/api/crons",
			Headers: map[string]string{
				"Authorization": superuserToken,
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`{"id":"__pbLogsCleanup__","expression":"0 */6 * * *"}`,
				`{"id":"__pbDBOptimize__","expression":"0 0 * * *"}`,
				`{"id":"__pbMFACleanup__","expression":"0 * * * *"}`,
				`{"id":"__pbOTPCleanup__","expression":"0 * * * *"}`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestCronsRun(t *testing.T) {
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

	beforeTestFunc := func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
		app.Cron().Add("test", "* * * * *", func() {
			app.Store().Set("testJobCalls", cast.ToInt(app.Store().Get("testJobCalls"))+1)
		})
	}

	expectedCalls := func(expected int) func(t testing.TB, app *tests.TestApp, res *http.Response) {
		return func(t testing.TB, app *tests.TestApp, res *http.Response) {
			total := cast.ToInt(app.Store().Get("testJobCalls"))
			if total != expected {
				t.Fatalf("Expected total testJobCalls %d, got %d", expected, total)
			}
		}
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "unauthorized",
			Method:          http.MethodPost,
			URL:             "/api/crons/test",
			Delay:           50 * time.Millisecond,
			BeforeTestFunc:  beforeTestFunc,
			AfterTestFunc:   expectedCalls(0),
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "authorized as regular user",
			Method: http.MethodPost,
			URL:    "/api/crons/test",
			Headers: map[string]string{
				"Authorization": user1Token,
			},
			Delay:           50 * time.Millisecond,
			BeforeTestFunc:  beforeTestFunc,
			AfterTestFunc:   expectedCalls(0),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "authorized as superuser (missing job)",
			Method: http.MethodPost,
			URL:    "/api/crons/missing",
			Headers: map[string]string{
				"Authorization": superuserToken,
			},
			Delay:           50 * time.Millisecond,
			BeforeTestFunc:  beforeTestFunc,
			AfterTestFunc:   expectedCalls(0),
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "authorized as superuser (existing job)",
			Method: http.MethodPost,
			URL:    "/api/crons/test",
			Headers: map[string]string{
				"Authorization": superuserToken,
			},
			Delay:          50 * time.Millisecond,
			BeforeTestFunc: beforeTestFunc,
			AfterTestFunc:  expectedCalls(1),
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}
