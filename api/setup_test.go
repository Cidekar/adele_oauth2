package api

import (
	"embed"
	"os"
	"testing"

	"github.com/cidekar/adele-framework"
	"github.com/cidekar/adele-framework/database"
	"github.com/cidekar/adele-framework/mux"
	"github.com/cidekar/adele-framework/render"
	"github.com/cidekar/adele-framework/session"
	"github.com/joho/godotenv"
	up "github.com/upper/db/v4"
)

// Run with from package root:
// go test . -v
// go test -coverprofile=coverage.out . && go tool cover -html=coverage.out
// go test . --run TestOauth_ChallengeCodeValidate

//go:embed testmigrations
var templateFS embed.FS

var (
	ade                    adele.Adele
	upper                  up.Session
	ClientCredentialsGrant Client
	OauthTkn               OauthToken
)

func TestMain(m *testing.M) {

	path, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	ade.RootPath = path + "/testdata"

	err = godotenv.Load(ade.RootPath + "/.test.env")
	if err != nil {
		panic(err)
	}

	// setup the database session
	dsn := &database.DataSourceName{
		Host:         "localhost",
		Port:         "5432",
		User:         "postgres",
		Password:     "password",
		DatabaseName: "test",
		SslMode:      "disable",
	}
	db, err := database.OpenDB(os.Getenv("DATABASE_TYPE"), dsn)
	if err != nil {
		panic(err)
	}
	ade.DB = &database.Database{
		DataType: os.Getenv("DATABASE_TYPE"),
		Pool:     db,
	}
	ade.Routes = mux.NewRouter()

	// setup session
	sess := session.Session{}
	ade.Session = sess.InitSession()

	// Renderer
	ade.Render = &render.Render{}

	upper = ade.DB.NewSession()

	// run the unit tests
	code := m.Run()

	os.Exit(code)
}
