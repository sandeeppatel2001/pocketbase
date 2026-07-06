package apis_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

func TestRecordCrudExternalAuthList(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	clientToken := mustAuthToken(t, app, "clients", "test@example.com")
	userToken := mustAuthToken(t, app, "users", "test2@example.com")

	scenarios := []tests.ApiScenario{
		{
			Name:           "guest",
			Method:         http.MethodGet,
			URL:            "/api/collections/" + core.CollectionNameExternalAuths + "/records",
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalItems":0`,
				`"totalPages":0`,
				`"items":[]`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
			},
		},
		{
			Name:   "regular auth with externalAuths",
			Method: http.MethodGet,
			URL:    "/api/collections/" + core.CollectionNameExternalAuths + "/records",
			Headers: map[string]string{
				// clients, test@example.com
				"Authorization": clientToken,
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalItems":1`,
				`"totalPages":1`,
				`"id":"f1z5b3843pzc964"`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
				"OnRecordEnrich":       1,
			},
		},
		{
			Name:   "regular auth without externalAuths",
			Method: http.MethodGet,
			URL:    "/api/collections/" + core.CollectionNameExternalAuths + "/records",
			Headers: map[string]string{
				// users, test2@example.com
				"Authorization": userToken,
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalItems":0`,
				`"totalPages":0`,
				`"items":[]`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
			},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestRecordCrudExternalAuthView(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	ownerToken := mustAuthToken(t, app, "users", "test@example.com")
	clientToken := mustAuthToken(t, app, "clients", "test@example.com")

	scenarios := []tests.ApiScenario{
		{
			Name:            "guest",
			Method:          http.MethodGet,
			URL:             "/api/collections/" + core.CollectionNameExternalAuths + "/records/dlmflokuq1xl342",
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "non-owner",
			Method: http.MethodGet,
			URL:    "/api/collections/" + core.CollectionNameExternalAuths + "/records/dlmflokuq1xl342",
			Headers: map[string]string{
				// clients, test@example.com
				"Authorization": clientToken,
			},
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "owner",
			Method: http.MethodGet,
			URL:    "/api/collections/" + core.CollectionNameExternalAuths + "/records/dlmflokuq1xl342",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": ownerToken,
			},
			ExpectedStatus:  200,
			ExpectedContent: []string{`"id":"dlmflokuq1xl342"`},
			ExpectedEvents: map[string]int{
				"*":                   0,
				"OnRecordViewRequest": 1,
				"OnRecordEnrich":      1,
			},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestRecordCrudExternalAuthDelete(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	ownerToken := mustAuthToken(t, app, "users", "test@example.com")
	clientToken := mustAuthToken(t, app, "clients", "test@example.com")

	scenarios := []tests.ApiScenario{
		{
			Name:            "guest",
			Method:          http.MethodDelete,
			URL:             "/api/collections/" + core.CollectionNameExternalAuths + "/records/dlmflokuq1xl342",
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "non-owner",
			Method: http.MethodDelete,
			URL:    "/api/collections/" + core.CollectionNameExternalAuths + "/records/dlmflokuq1xl342",
			Headers: map[string]string{
				// clients, test@example.com
				"Authorization": clientToken,
			},
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "owner",
			Method: http.MethodDelete,
			URL:    "/api/collections/" + core.CollectionNameExternalAuths + "/records/dlmflokuq1xl342",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": ownerToken,
			},
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordDeleteRequest":      1,
				"OnModelDelete":              1,
				"OnModelDeleteExecute":       1,
				"OnModelAfterDeleteSuccess":  1,
				"OnRecordDelete":             1,
				"OnRecordDeleteExecute":      1,
				"OnRecordAfterDeleteSuccess": 1,
			},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestRecordCrudExternalAuthCreate(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	ownerToken := mustAuthToken(t, app, "users", "test@example.com")
	superuserToken := mustAuthToken(t, app, core.CollectionNameSuperusers, "test@example.com")

	body := func() *strings.Reader {
		return strings.NewReader(`{
			"recordRef":     "4q1xlclmfloku33",
			"collectionRef": "_pb_users_auth_",
			"provider":      "github",
			"providerId":    "abc"
		}`)
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "guest",
			Method:          http.MethodPost,
			URL:             "/api/collections/" + core.CollectionNameExternalAuths + "/records",
			Body:            body(),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "owner regular auth",
			Method: http.MethodPost,
			URL:    "/api/collections/" + core.CollectionNameExternalAuths + "/records",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": ownerToken,
			},
			Body:            body(),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "superusers auth",
			Method: http.MethodPost,
			URL:    "/api/collections/" + core.CollectionNameExternalAuths + "/records",
			Headers: map[string]string{
				// superusers, test@example.com
				"Authorization": superuserToken,
			},
			Body: body(),
			ExpectedContent: []string{
				`"recordRef":"4q1xlclmfloku33"`,
				`"providerId":"abc"`,
			},
			ExpectedStatus: 200,
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordCreateRequest":      1,
				"OnRecordEnrich":             1,
				"OnModelCreate":              1,
				"OnModelCreateExecute":       1,
				"OnModelAfterCreateSuccess":  1,
				"OnModelValidate":            1,
				"OnRecordCreate":             1,
				"OnRecordCreateExecute":      1,
				"OnRecordAfterCreateSuccess": 1,
				"OnRecordValidate":           1,
			},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestRecordCrudExternalAuthUpdate(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	clientToken := mustAuthToken(t, app, "clients", "test@example.com")
	superuserToken := mustAuthToken(t, app, core.CollectionNameSuperusers, "test@example.com")

	body := func() *strings.Reader {
		return strings.NewReader(`{
			"providerId": "abc"
		}`)
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "guest",
			Method:          http.MethodPatch,
			URL:             "/api/collections/" + core.CollectionNameExternalAuths + "/records/dlmflokuq1xl342",
			Body:            body(),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "owner regular auth",
			Method: http.MethodPatch,
			URL:    "/api/collections/" + core.CollectionNameExternalAuths + "/records/dlmflokuq1xl342",
			Headers: map[string]string{
				// clients, test@example.com
				"Authorization": clientToken,
			},
			Body:            body(),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "superusers auth",
			Method: http.MethodPatch,
			URL:    "/api/collections/" + core.CollectionNameExternalAuths + "/records/dlmflokuq1xl342",
			Headers: map[string]string{
				// superusers, test@example.com
				"Authorization": superuserToken,
			},
			Body: body(),
			ExpectedContent: []string{
				`"id":"dlmflokuq1xl342"`,
				`"providerId":"abc"`,
			},
			ExpectedStatus: 200,
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordUpdateRequest":      1,
				"OnRecordEnrich":             1,
				"OnModelUpdate":              1,
				"OnModelUpdateExecute":       1,
				"OnModelAfterUpdateSuccess":  1,
				"OnModelValidate":            1,
				"OnRecordUpdate":             1,
				"OnRecordUpdateExecute":      1,
				"OnRecordAfterUpdateSuccess": 1,
				"OnRecordValidate":           1,
			},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func mustAuthToken(t *testing.T, app *tests.TestApp, collection, email string) string {
	t.Helper()

	record, err := app.FindAuthRecordByEmail(collection, email)
	if err != nil {
		t.Fatal(err)
	}

	token, err := record.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}

	return token
}
