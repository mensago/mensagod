package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/darkwyrm/mensagod/logging"
	"github.com/everlastingbeta/diceware"
	"github.com/everlastingbeta/diceware/wordlist"
	"github.com/spf13/viper"
)

var gSetupInit bool

// SetupConfig initializes and loads the server's global configuration options
func SetupConfig() diceware.Wordlist {

	var outList diceware.Wordlist
	if gSetupInit {
		switch viper.GetString("security.diceware_wordlist") {
		case "eff_short":
			outList = wordlist.EFFShort
		case "eff_short_prefix":
			outList = wordlist.EFFShortPrefix
		case "eff_long":
			outList = wordlist.EFFLong
		case "original":
			outList = wordlist.Original
		default:
			logging.Write("Invalid word list in config file. Exiting.")
			logging.Shutdown()
			os.Exit(1)
		}
		return outList
	}

	// IP and port to listen on
	viper.SetDefault("network.listen_ip", "127.0.0.1")
	viper.SetDefault("network.port", "2001")

	// Database config
	viper.SetDefault("database.engine", "postgresql")
	viper.SetDefault("database.ip", "127.0.0.1")
	viper.SetDefault("database.port", "5432")
	viper.SetDefault("database.name", "mensago")
	viper.SetDefault("database.user", "mensago")
	viper.SetDefault("database.password", "")

	// Location of workspace data, server log
	switch runtime.GOOS {
	case "js", "nacl":
		fmt.Println("Javascript and NaCl are not supported platforms for Mensago Server.")
		os.Exit(1)
	case "windows":
		programData, success := os.LookupEnv("ProgramData")
		if !success {
			programData = "C:\\ProgramData"
		}

		viper.SetDefault("global.workspace_dir", filepath.Join(programData, "mensago"))
		viper.Set("global.log_dir", filepath.Join(programData, "mensagod"))
		viper.SetConfigName("serverconfig")
		viper.AddConfigPath(filepath.Join(programData, "mensagod"))
	default:
		viper.SetDefault("global.workspace_dir", "/var/mensago/")
		viper.Set("global.log_dir", "/var/log/mensagod/")
		viper.SetConfigName("serverconfig")
		viper.AddConfigPath("/etc/mensagod/")
	}

	// Account registration modes
	// public - Outside registration requests.
	// network - registration is public, but restricted to a subnet or single IP address
	// moderated - A registration request is sent and a moderator must approve the account
	//			   prior to its creation
	// private - an account can be created only by an administrator -- outside requests will bounce
	viper.SetDefault("global.registration", "private")

	// Subnet(s) used for network registration. Defaults to private networks only.
	viper.SetDefault("global.registration_subnet",
		"192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8, 127.0.0.1/8")
	viper.SetDefault("global.registration_subnet6", "fe80::/10")

	// Default user workspace quota in MiB. 0 = no quota
	viper.SetDefault("global.default_quota", 0)

	// Max item size in MiB.
	viper.SetDefault("global.max_file_size", 50)

	// Max message size in MiB. max_file_size takes precedence over this value
	viper.SetDefault("global.max_message_size", 50)

	// Max age of sync records in days. Any records older than the oldest device login timestamp
	// minus this number of days are purged. Defaults to 1 week, which should be plenty.
	viper.SetDefault("global.max_sync_age", 7)

	// Diceware settings for registration code and password reset code generation
	viper.SetDefault("security.diceware_wordlist", "eff_short_prefix")
	viper.SetDefault("security.diceware_wordcount", 6)

	// Delay after an unsuccessful login
	viper.SetDefault("security.failure_delay_sec", 3)

	// Max number of login failures before the connection is closed
	viper.SetDefault("security.max_failures", 5)

	// Lockout time (in minutes) after max_failures exceeded
	viper.SetDefault("security.lockout_delay_min", 15)

	// Delay (in minutes) the number of minutes which must pass before another account registration
	// can be requested from the same IP address -- for preventing registration spam/DoS.
	viper.SetDefault("security.registration_delay_min", 15)

	// Default expiration time for password resets
	viper.SetDefault("security.password_reset_min", 60)

	// Resource usage for password hashing
	viper.SetDefault("security.password_security", "normal")

	// Read the config file
	err := viper.ReadInConfig()
	if err != nil {
		fmt.Printf("Unable to locate config file. Exiting. Error: %s", err)
		os.Exit(1)
	}

	logLocation := filepath.Join(viper.GetString("global.log_dir"), "mensagod.log")
	if _, err := os.Stat(viper.GetString("global.log_dir")); os.IsNotExist(err) {
		err = os.Mkdir(viper.GetString("global.log_dir"), 0600)
		if err != nil {
			fmt.Printf("Unable to create log directory %s. Exiting. Error: %s",
				viper.GetString("global.log_dir"), err)
			os.Exit(1)
		}
	}

	logging.Init(logLocation, true)

	_, err = os.Stat(viper.GetString("global.workspace_dir"))
	if os.IsNotExist(err) {
		err = os.Mkdir(viper.GetString("global.workspace_dir"), 0600)
		if err != nil {
			fmt.Printf("Unable to create workspace directory %s. Exiting. Error: %s",
				viper.GetString("global.workspace_dir"), err)
			os.Exit(1)
		}
	}

	tempDirPath := filepath.Join(viper.GetString("global.workspace_dir"), "tmp")
	_, err = os.Stat(tempDirPath)
	if os.IsNotExist(err) {
		err = os.Mkdir(tempDirPath, 0600)
		if err != nil {
			fmt.Printf("Unable to create workspace temporary directory %s. Exiting. Error: %s",
				tempDirPath, err)
			os.Exit(1)
		}
	}

	if viper.GetString("database.password") == "" {
		logging.Write("Database password not set in config file. Exiting.")
		logging.Shutdown()
		os.Exit(1)
	}

	pattern := regexp.MustCompile("([a-zA-Z0-9]+\x2E)+[a-zA-Z0-9]+")
	if viper.GetString("global.domain") == "" ||
		!pattern.MatchString(viper.GetString("global.domain")) {
		logging.Write("Missing or invalid domain in config file. Exiting.")
		logging.Shutdown()
		os.Exit(1)
	}

	switch viper.GetString("global.registration") {
	case "private", "public", "network", "moderated":
		// Do nothing. Legitimate values.
	default:
		logging.Write("Invalid registration mode in config file. Exiting.")
		logging.Shutdown()
		os.Exit(1)
	}

	switch viper.GetString("security.diceware_wordlist") {
	case "eff_short":
		outList = wordlist.EFFShort
	case "eff_short_prefix":
		outList = wordlist.EFFShortPrefix
	case "eff_long":
		outList = wordlist.EFFLong
	case "original":
		outList = wordlist.Original
	default:
		logging.Write("Invalid word list in config file. Exiting.")
		logging.Shutdown()
		os.Exit(1)
	}

	if viper.GetInt("security.diceware_wordcount") < 3 ||
		viper.GetInt("security.diceware_wordcount") > 12 {
		viper.Set("security.diceware_wordcount", 6)
		logging.Write("Registration wordcount out of bounds in config file. Assuming 6.")
	}

	if viper.GetInt("global.default_quota") < 0 {
		viper.Set("global.default_quota", 0)
		logging.Write("Negative quota value in config file. Assuming zero.")
	}

	if viper.GetInt("security.failure_delay_sec") > 60 {
		viper.Set("security.failure_delay_sec", 60)
		logging.Write("Limiting maximum failure delay to 60.")
	}

	if viper.GetInt("security.max_failures") < 1 {
		viper.Set("security.max_failures", 1)
		logging.Write("Invalid login failure maximum. Setting to 1.")
	} else if viper.GetInt("security.max_failures") > 10 {
		viper.Set("security.max_failures", 10)
		logging.Write("Limiting login failure maximum to 10.")
	}

	if viper.GetInt("security.lockout_delay_min") < 0 {
		viper.Set("security.lockout_delay_min", 0)
		logging.Write("Negative login failure lockout time. Setting to zero.")
	}

	if viper.GetInt("security.registration_delay_min") < 0 {
		viper.Set("security.registration_delay_min", 0)
		logging.Write("Negative registration delay. Setting to zero.")
	}

	if viper.GetInt("security.password_reset_min") < 10 ||
		viper.GetInt("security.password_reset_min") > 2880 {
		viper.Set("security.password_reset_min", 60)
		logging.Write("Invalid password reset time. Setting to 60.")
	}

	gSetupInit = true

	return outList
}
