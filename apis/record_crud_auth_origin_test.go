package apis_test

import (
	"net/http"
	"strings"
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

func mustAuthHeader(t testing.TB, app *tests.TestApp, collectionName, email string) map[string]string {
	return map[string]string{
		"Authorization": mustAuthToken(t, app, collectionName, email),
	}
}

func TestRecordCrudAuthOriginList(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	ownerHeaders := mustAuthHeader(t, app, "clients", "test@example.com")
	nonOwnerHeaders := mustAuthHeader(t, app, "users", "test@example.com")
	factory := func(testing.TB) *tests.TestApp { return app }

	scenarios := []tests.ApiScenario{
		{
			Name:           "guest",
			Method:         http.MethodGet,
			URL:            "/api/collections/" + core.CollectionNameAuthOrigins + "/records",
			TestAppFactory: factory,
			DisableTestAppCleanup: true,
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
			Name:   "regular auth with authOrigins",
			Method: http.MethodGet,
			URL:    "/api/collections/" + core.CollectionNameAuthOrigins + "/records",
			Headers: ownerHeaders,
			TestAppFactory: factory,
			DisableTestAppCleanup: true,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalItems":1`,
				`"totalPages":1`,
				`"id":"9r2j0m74260ur8i"`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
				"OnRecordEnrich":       1,
			},
		},
		{
			Name:   "regular auth without authOrigins",
			Method: http.MethodGet,
			URL:    "/api/collections/" + core.CollectionNameAuthOrigins + "/records",
			Headers: nonOwnerHeaders,
			TestAppFactory: factory,
			DisableTestAppCleanup: true,
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

func TestRecordCrudAuthOriginView(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	ownerHeaders := mustAuthHeader(t, app, "clients", "test@example.com")
	nonOwnerHeaders := mustAuthHeader(t, app, "users", "test@example.com")
	factory := func(testing.TB) *tests.TestApp { return app }

	scenarios := []tests.ApiScenario{
		{
			Name:            "guest",
			Method:          http.MethodGet,
			URL:             "/api/collections/" + core.CollectionNameAuthOrigins + "/records/9r2j0m74260ur8i",
			TestAppFactory: factory,
			DisableTestAppCleanup: true,
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "non-owner",
			Method: http.MethodGet,
			URL:    "/api/collections/" + core.CollectionNameAuthOrigins + "/records/9r2j0m74260ur8i",
			Headers: nonOwnerHeaders,
			TestAppFactory: factory,
			DisableTestAppCleanup: true,
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "owner",
			Method: http.MethodGet,
			URL:    "/api/collections/" + core.CollectionNameAuthOrigins + "/records/9r2j0m74260ur8i",
			Headers: ownerHeaders,
			TestAppFactory: factory,
			DisableTestAppCleanup: true,
			ExpectedStatus:  200,
			ExpectedContent: []string{`"id":"9r2j0m74260ur8i"`},
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

func TestRecordCrudAuthOriginDelete(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	ownerHeaders := mustAuthHeader(t, app, "clients", "test@example.com")
	nonOwnerHeaders := mustAuthHeader(t, app, "users", "test@example.com")
	factory := func(testing.TB) *tests.TestApp { return app }

	scenarios := []tests.ApiScenario{
		{
			Name:            "guest",
			Method:          http.MethodDelete,
			URL:             "/api/collections/" + core.CollectionNameAuthOrigins + "/records/9r2j0m74260ur8i",
			TestAppFactory: factory,
			DisableTestAppCleanup: true,
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "non-owner",
			Method: http.MethodDelete,
			URL:    "/api/collections/" + core.CollectionNameAuthOrigins + "/records/9r2j0m74260ur8i",
			Headers: nonOwnerHeaders,
			TestAppFactory: factory,
			DisableTestAppCleanup: true,
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "owner",
			Method: http.MethodDelete,
			URL:    "/api/collections/" + core.CollectionNameAuthOrigins + "/records/9r2j0m74260ur8i",
			Headers: ownerHeaders,
			TestAppFactory: factory,
			DisableTestAppCleanup: true,
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

func TestRecordCrudAuthOriginCreate(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	body := func() *strings.Reader {
		return strings.NewReader(`{
			"recordRef":     "4q1xlclmfloku33",
			"collectionRef": "_pb_users_auth_",
			"fingerprint":   "abc"
		}`)
	}

	ownerHeaders := mustAuthHeader(t, app, "clients", "test@example.com")
	superuserHeaders := mustAuthHeader(t, app, core.CollectionNameSuperusers, "test@example.com")
	factory := func(testing.TB) *tests.TestApp { return app }

	scenarios := []tests.ApiScenario{
		{
			Name:            "guest",
			Method:          http.MethodPost,
			URL:             "/api/collections/" + core.CollectionNameAuthOrigins + "/records",
			Body:            body(),
			TestAppFactory: factory,
			DisableTestAppCleanup: true,
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "owner regular auth",
			Method: http.MethodPost,
			URL:    "/api/collections/" + core.CollectionNameAuthOrigins + "/records",
			Headers: ownerHeaders,
			TestAppFactory: factory,
			DisableTestAppCleanup: true,
			Body:            body(),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "superusers auth",
			Method: http.MethodPost,
			URL:    "/api/collections/" + core.CollectionNameAuthOrigins + "/records",
			Headers: superuserHeaders,
			TestAppFactory: factory,
			DisableTestAppCleanup: true,
			Body: body(),
			ExpectedContent: []string{
				`"fingerprint":"abc"`,
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

func TestRecordCrudAuthOriginUpdate(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	body := func() *strings.Reader {
		return strings.NewReader(`{
			"fingerprint":"abc"
		}`)
	}

	ownerHeaders := mustAuthHeader(t, app, "clients", "test@example.com")
	superuserHeaders := mustAuthHeader(t, app, core.CollectionNameSuperusers, "test@example.com")
	factory := func(testing.TB) *tests.TestApp { return app }

	scenarios := []tests.ApiScenario{
		{
			Name:            "guest",
			Method:          http.MethodPatch,
			URL:             "/api/collections/" + core.CollectionNameAuthOrigins + "/records/9r2j0m74260ur8i",
			Body:            body(),
			TestAppFactory: factory,
			DisableTestAppCleanup: true,
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "owner regular auth",
			Method: http.MethodPatch,
			URL:    "/api/collections/" + core.CollectionNameAuthOrigins + "/records/9r2j0m74260ur8i",
			Headers: ownerHeaders,
			TestAppFactory: factory,
			DisableTestAppCleanup: true,
			Body:            body(),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "superusers auth",
			Method: http.MethodPatch,
			URL:    "/api/collections/" + core.CollectionNameAuthOrigins + "/records/9r2j0m74260ur8i",
			Headers: superuserHeaders,
			TestAppFactory: factory,
			DisableTestAppCleanup: true,
			Body: body(),
			ExpectedContent: []string{
				`"id":"9r2j0m74260ur8i"`,
				`"fingerprint":"abc"`,
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
