package apis_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

func TestRecordAuthImpersonate(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	user1, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	user1Token, err := user1.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}

	user2, err := app.FindAuthRecordByEmail("users", "test2@example.com")
	if err != nil {
		t.Fatal(err)
	}
	user2Token, err := user2.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}

	superuser, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	superuserToken, err := superuser.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "unauthorized",
			Method:          http.MethodPost,
			URL:             "/api/collections/users/impersonate/4q1xlclmfloku33",
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "authorized as different user",
			Method: http.MethodPost,
			URL:    "/api/collections/users/impersonate/4q1xlclmfloku33",
			Headers: map[string]string{
				"Authorization": user2Token,
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "authorized as the same user",
			Method: http.MethodPost,
			URL:    "/api/collections/users/impersonate/4q1xlclmfloku33",
			Headers: map[string]string{
				"Authorization": user1Token,
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "authorized as superuser",
			Method: http.MethodPost,
			URL:    "/api/collections/users/impersonate/4q1xlclmfloku33",
			Headers: map[string]string{
				"Authorization": superuserToken,
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"token":"`,
				`"id":"4q1xlclmfloku33"`,
				`"record":{`,
			},
			NotExpectedContent: []string{
				// hidden fields should remain hidden even though we are authenticated as superuser
				`"tokenKey"`,
				`"password"`,
			},
			ExpectedEvents: map[string]int{
				"*":                   0,
				"OnRecordAuthRequest": 1,
				"OnRecordEnrich":      1,
			},
		},
		{
			Name:   "authorized as superuser with custom invalid duration",
			Method: http.MethodPost,
			URL:    "/api/collections/users/impersonate/4q1xlclmfloku33",
			Headers: map[string]string{
				"Authorization": superuserToken,
			},
			Body:           strings.NewReader(`{"duration":-1}`),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"duration":{`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "authorized as superuser with custom valid duration",
			Method: http.MethodPost,
			URL:    "/api/collections/users/impersonate/4q1xlclmfloku33",
			Headers: map[string]string{
				"Authorization": superuserToken,
			},
			Body:           strings.NewReader(`{"duration":100}`),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"token":"`,
				`"id":"4q1xlclmfloku33"`,
				`"record":{`,
			},
			ExpectedEvents: map[string]int{
				"*":                   0,
				"OnRecordAuthRequest": 1,
				"OnRecordEnrich":      1,
			},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}
