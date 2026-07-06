package apis_test

import (
	"net/http"
	"testing"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

func TestHealthAPI(t *testing.T) {
	t.Parallel()

	regularUserAuthToken := mustInitAuthToken("users", "test@example.com", false)
	superuserAuthToken := mustInitAuthToken(core.CollectionNameSuperusers, "test@example.com", false)

	scenarios := []tests.ApiScenario{
		{
			Name:           "GET health status (guest)",
			Method:         http.MethodGet, // automatically matches also HEAD as a side-effect of the Go std mux
			URL:            "/api/health",
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"code":200`,
				`"data":{}`,
			},
			NotExpectedContent: []string{
				"canBackup",
				"realIP",
				"possibleProxyHeader",
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "GET health status (regular user)",
			Method: http.MethodGet,
			URL:    "/api/health",
			Headers: map[string]string{
				"Authorization": regularUserAuthToken,
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"code":200`,
				`"data":{}`,
			},
			NotExpectedContent: []string{
				"canBackup",
				"realIP",
				"possibleProxyHeader",
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "GET health status (superuser)",
			Method: http.MethodGet,
			URL:    "/api/health",
			Headers: map[string]string{
				"Authorization": superuserAuthToken,
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"code":200`,
				`"data":{`,
				`"canBackup":true`,
				`"realIP"`,
				`"possibleProxyHeader"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}
