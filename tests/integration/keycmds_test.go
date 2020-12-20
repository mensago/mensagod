package anselusd

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	_ "github.com/lib/pq"
	"github.com/spf13/viper"
)

func readConfig() {
	// IP and port to listen on
	viper.SetDefault("network.listen_ip", "127.0.0.1")
	viper.SetDefault("network.port", "2001")

	// Database config
	viper.SetDefault("database.engine", "postgresql")
	viper.SetDefault("database.ip", "127.0.0.1")
	viper.SetDefault("database.port", "5432")
	viper.SetDefault("database.name", "anselus")
	viper.SetDefault("database.user", "anselus")
	viper.SetDefault("database.password", "")

	switch runtime.GOOS {
	case "js", "nacl":
		fmt.Println("Javascript and NaCl are not supported platforms for Anselus Server.")
		os.Exit(1)
	case "windows":
		programData, success := os.LookupEnv("ProgramData")
		if !success {
			programData = "C:\\ProgramData"
		}

		viper.SetDefault("global.workspace_dir", filepath.Join(programData, "anselus"))
		viper.Set("global.log_dir", filepath.Join(programData, "anselusd"))
		viper.SetConfigName("serverconfig")
		viper.AddConfigPath(filepath.Join(programData, "anselusd"))
	default:
		viper.SetDefault("global.workspace_dir", "/var/anselus/")
		viper.Set("global.log_dir", "/var/log/anselusd/")
		viper.SetConfigName("serverconfig")
		viper.AddConfigPath("/etc/anselusd/")
	}

	err := viper.ReadInConfig()
	if err != nil {
		fmt.Printf("Unable to locate config file. Exiting. Error: %s", err)
		os.Exit(1)
	}
}

func TestOrgCard(t *testing.T) {
	readConfig()

	connString := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		viper.GetString("database.ip"), viper.GetString("database.port"),
		viper.GetString("database.user"), viper.GetString("database.password"),
		viper.GetString("database.name"))

	dbConn, err := sql.Open("postgres", connString)
	if err != nil {
		t.Fatalf("TestOrgCard: failed to connect to database: %s\n", err)
	}
	// Calling Ping() is required because Open() just validates the settings passed
	err = dbConn.Ping()
	if err != nil {
		t.Fatalf("TestOrgCard: failed to connect to database: %s\n", err)
	}
}
