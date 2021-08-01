package integrationtests

import (
	"net/http"
	"os"
	"time"

	"github.com/mattermost/focalboard/server/client"
	"github.com/mattermost/focalboard/server/server"
	"github.com/mattermost/focalboard/server/services/config"
	"github.com/mattermost/focalboard/server/services/mlog"
)

type TestHelper struct {
	Server *server.Server
	Client *client.Client
}

func getTestConfig() *config.Configuration {
	dbType := os.Getenv("FB_STORE_TEST_DB_TYPE")
	if dbType == "" {
		dbType = "sqlite3"
	}

	connectionString := os.Getenv("FB_STORE_TEST_CONN_STRING")
	if connectionString == "" {
		connectionString = ":memory:"
	}

	logging := `
	{
		"testing": {
			"type": "console",
			"options": {
				"out": "stdout"
			},
			"format": "plain",
			"format_options": {
				"delim": "  "
			},
			"levels": [
				{"id": 5, "name": "debug"},
				{"id": 4, "name": "info"},
				{"id": 3, "name": "warn"},
				{"id": 2, "name": "error", "stacktrace": true},
				{"id": 1, "name": "fatal", "stacktrace": true},
				{"id": 0, "name": "panic", "stacktrace": true}
			]
		}
	}`

	return &config.Configuration{
		ServerRoot:        "http://localhost.charlesproxy.com:8888",
		Port:              8888,
		DBType:            dbType,
		DBConfigString:    connectionString,
		DBTablePrefix:     "test_",
		WebPath:           "./pack",
		FilesDriver:       "local",
		FilesPath:         "./files",
		LoggingCfgJSON:    logging,
		SessionExpireTime: int64(30 * time.Second),
		AuthMode:          "native",
	}
}

func newTestServer(singleUserToken string) *server.Server {
	logger := mlog.NewLogger()
	if err := logger.Configure("", getTestConfig().LoggingCfgJSON); err != nil {
		panic(err)
	}
	cfg := getTestConfig()
	db, err := server.NewStore(cfg, logger)
	if err != nil {
		panic(err)
	}
	srv, err := server.New(cfg, singleUserToken, db, logger)
	if err != nil {
		panic(err)
	}

	return srv
}

func SetupTestHelper() *TestHelper {
	sessionToken := "TESTTOKEN"
	th := &TestHelper{}
	th.Server = newTestServer(sessionToken)
	th.Client = client.NewClient(th.Server.Config().ServerRoot, sessionToken)
	return th
}

func SetupTestHelperWithoutToken() *TestHelper {
	th := &TestHelper{}
	th.Server = newTestServer("")
	th.Client = client.NewClient(th.Server.Config().ServerRoot, "")
	return th
}

func (th *TestHelper) InitBasic() *TestHelper {
	go func() {
		if err := th.Server.Start(); err != nil {
			panic(err)
		}
	}()

	for {
		URL := th.Server.Config().ServerRoot
		th.Server.Logger().Info("Polling server", mlog.String("url", URL))
		resp, err := http.Get(URL) //nolint:gosec
		if err != nil {
			th.Server.Logger().Error("Polling failed", mlog.Err(err))
			time.Sleep(100 * time.Millisecond)
			continue
		}
		resp.Body.Close()

		// Currently returns 404
		// if resp.StatusCode != http.StatusOK {
		// 	th.Server.Logger().Error("Not OK", mlog.Int("statusCode", resp.StatusCode))
		// 	continue
		// }

		// Reached this point: server is up and running!
		th.Server.Logger().Info("Server ping OK", mlog.Int("statusCode", resp.StatusCode))

		break
	}

	return th
}

func (th *TestHelper) TearDown() {
	defer func() { _ = th.Server.Logger().Shutdown() }()

	err := th.Server.Shutdown()
	if err != nil {
		panic(err)
	}
}
