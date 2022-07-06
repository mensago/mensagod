package main

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gitlab.com/darkwyrm/b85"
	"gitlab.com/mensago/mensagod/dbhandler"
	"golang.org/x/crypto/argon2"
)

var (
	connected bool
	dbConn    *sql.DB
)

func DeriveKey(password string) map[string]string {
	out := make(map[string]string)

	// Ensuring password complexity is not in scope of this function. We're preventing only
	// empty passwords from being used here.
	if len(password) < 1 {
		return out
	}

	// Generate the salt using a cryptographically-secure method provided by the OS
	salt := make([]byte, 16)
	rand.Read(salt)

	var timeNeeded uint32 = 1
	var memlimit uint32 = 64 * 1024
	var threadCount uint8 = 4
	var keyLength uint32 = 32

	key := argon2.IDKey([]byte(password), salt, timeNeeded, memlimit, threadCount, keyLength)

	out["algorithm"] = "argon2id"
	out["memory"] = "65536"
	out["time"] = "1"
	out["salt"] = b85.Encode(salt)
	out["key"] = b85.Encode(key)

	return out
}

// SetupConfigFile is used to obtain the necessary information from the user for creating the
// server config file
func SetupConfigFile() {

	switch runtime.GOOS {
	case "js", "android", "ios":
		fmt.Println("Javascript, Android, and iOS are not supported platforms.")
		os.Exit(2)
	case "windows":
		handle, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		if err != nil {
			fmt.Println("Setup mode requires administrator privileges")
			os.Exit(1)
		}
		handle.Close()
	default:
		currentUser, err := user.Current()
		if err != nil {
			panic("unable to get current user. aborting.")
		}
		if currentUser.Username != "root" {
			fmt.Println("Setup mode requires root privileges")
			os.Exit(1)
		}
	}

	fmt.Print("This script generates the first-time setup for a new mensagod\n" +
		"server. Depending on the requirements of your environment, you\n" +
		"may need to edit the config file afterward.\n\n" +

		"The database will be emptied and reset, but any existing config file will be\n" +
		"backed up.\n\n")

	config := make(map[string]string)

	var tempStr string

	if runtime.GOOS == "windows" {
		programData := ""
		for _, s := range os.Environ() {
			if strings.HasPrefix(s, "ProgramData") {
				parts := strings.Split(s, "=")
				programData = parts[1]
				break
			}
		}

		config["config_path"] = programData + "\\sra"
		config["log_path"] = programData + "\\sra"
	} else {
		config["config_path"] = "/etc/sra"
		config["log_path"] = "/var/log/sra"

		fmt.Print("Enter the name of the user to run the server as. [mensagod]: ")
		if len, _ := fmt.Scanln(&tempStr); len == 0 {
			tempStr = "mensagod"
		}
		config["server_user"] = tempStr

		fmt.Print("Enter the name of the group for the server user. [mensago]: ")
		if len, _ := fmt.Scanln(&tempStr); len == 0 {
			tempStr = "mensagod"
		}
		config["server_group"] = tempStr
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}

	fmt.Printf("\nEnter the name of this server used in its TLS certificate. [%s]: ", hostname)
	if len, _ := fmt.Scanln(&tempStr); len == 0 {
		tempStr = hostname
	}
	config["server_name"] = tempStr

	fmt.Print("\nEnter the IP address of the database server. [localhost]: ")
	if len, _ := fmt.Scanln(&tempStr); len == 0 {
		tempStr = "localhost"
	}
	config["server_ip"] = tempStr

	fmt.Print("Enter the database server port. [5432]: ")
	if len, _ := fmt.Scanln(&tempStr); len == 0 {
		tempStr = "5432"
	}
	config["server_port"] = tempStr

	fmt.Print("Enter the name of the database to store data. [sra]: ")
	if len, _ := fmt.Scanln(&tempStr); len == 0 {
		tempStr = "mensago"
	}
	config["db_name"] = tempStr

	fmt.Print("Enter a username which has admin privileges on this database. [sra]: ")
	if len, _ := fmt.Scanln(&tempStr); len == 0 {
		tempStr = "mensagod"
	}
	config["db_user"] = tempStr

	config["db_password"] = ""
	for config["db_password"] == "" {
		fmt.Print("Enter the password of this user (min 8 characters): ")
		fmt.Scanln(&tempStr)
		if len(tempStr) <= 64 && len(tempStr) >= 8 {
			config["db_password"] = tempStr
		}
	}

	connString := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		config["server_ip"], config["server_port"], config["db_user"], config["db_password"],
		config["db_name"])

	dbhandler.ConnectWithString(connString)
	db := dbhandler.GetConnection()
	if db == nil {
		fmt.Println("Couldn't connect to database. Unable to continue until connectivity problems" +
			"are resolved")
		os.Exit(1)
	}

	if !dbhandler.IsEmpty() {
		fmt.Printf(`
================================================================================
                        WARNING: the database is not empty!
================================================================================

If you continue, ALL DATA WILL BE DELETED FROM THE DATABASE, which means all
users, inventory, and other information will be erased.
`)

		fmt.Print("Do you want to DELETE ALL DATA and continue? [y/N]: ")
		fmt.Scanln(&tempStr)
		tempStr = strings.ToLower(tempStr)
		if !(tempStr == "y" || tempStr == "yes") {
			os.Exit(0)
		}

		if err := dbhandler.Reset(); err != nil {
			fmt.Printf("Failed to reset database: %s", err.Error())
			os.Exit(1)
		}
	}

	// Now that we have all the information we need from the user and the database is ready for us,
	// configure the system and create the server config file.

	if runtime.GOOS != "windows" {

		// Set up the group the server's user will run in
		_, err := user.LookupGroup(config["server_group"])
		if err != nil {
			var groupError *user.UnknownGroupError
			if !errors.As(err, &groupError) {
				fmt.Printf("Unable to determine if group %s exists. Aborting.",
					config["server_group"])
				os.Exit(2)
			}

			args := []string{"--system", config["server_group"]}
			cmd := exec.Command("groupadd", args...)

			output, err := cmd.CombinedOutput()
			if output != nil || err != nil {
				fmt.Printf("Unable to create group '%s'. Error: %s\n"+
					"Please resolve and rerun this command", config["server_group"], output)
				os.Exit(1)
			}
		}

		// Set up the user the server will run as
		_, err = user.LookupGroup(config["server_user"])
		if err != nil {
			var userError *user.UnknownUserError
			if !errors.As(err, &userError) {
				fmt.Printf("Unable to determine if user %s exists. Aborting.",
					config["server_user"])
				os.Exit(2)
			}

			args := []string{"-M", "-g", config["server_group"], "--system", "-s", "/bin/false",
				config["server_user"]}
			cmd := exec.Command("useradd", args...)

			output, err := cmd.CombinedOutput()
			if output != nil || err != nil {
				fmt.Printf("Unable to create user '%s'. Error: %s\n"+
					"Please resolve and rerun this command", config["server_user"], output)
				os.Exit(1)
			}
		}
	}

	if _, err := os.Stat(config["config_path"]); err != nil {
		if err = os.MkdirAll(config["config_path"], os.ModePerm); err != nil {
			fmt.Printf("Unable to create directory '%s'. Error: %s\n"+
				"Please resolve and rerun this command", config["config_path"], err.Error())
			os.Exit(1)
		}
	}

	if _, err := os.Stat(config["log_path"]); err != nil {
		if err = os.MkdirAll(config["log_path"], os.ModePerm); err != nil {
			fmt.Printf("Unable to create directory '%s'. Error: %s\n"+
				"Please resolve and rerun this command", config["log_path"], err.Error())
			os.Exit(1)
		}

		group, err := user.LookupGroup(config["server_group"])
		if err != nil {
			fmt.Printf("Unable to find group %s exists. Aborting.", config["server_group"])
			os.Exit(2)
		}
		gid, err := strconv.Atoi(group.Gid)
		if err != nil {
			fmt.Printf("Invalid group ID %s received from system for group %s. Aborting.",
				group.Gid, config["server_group"])
			os.Exit(2)
		}
		err = os.Chown(config["log_path"], os.Getuid(), gid)
		if err != nil {
			fmt.Printf("Failed to set owner/group for log directory %s. "+
				"Please resolve and rerun this command. Error: %s", config["log_path"], err.Error())
			os.Exit(2)
		}
	}

	// Save the config file

	configFilePath := filepath.Join(config["config_path"], "serverconfig.toml")
	if _, err := os.Stat(configFilePath); err == nil {
		backupName := fmt.Sprintf("serverconfig.toml.%s", time.Now().Format("20060102T150405Z"))
		fmt.Printf("Config file %s exists. Renaming to %s\n", configFilePath, backupName)
		err := os.Rename(configFilePath, filepath.Join(configFilePath, backupName))
		if err != nil {
			fmt.Println("Error backing up the server config file: " + err.Error())
			fmt.Println("You will need to resolve this and re-run this command.")
			os.Exit(1)
		}
	}

	fHandle, err := os.Create(configFilePath)
	if err != nil {
		fmt.Println("Error creating the server config file: " + err.Error())
		fmt.Println("You will need to resolve this and re-run this command.")
		os.Exit(1)
	}
	defer fHandle.Close()

	fHandle.WriteString(`# This is config file for the Simple Remote Administrator
# server. Each value listed below is the default value. Every effort has been
# made to set this file to sensible defaults so that configuration is kept to
# a minimum. This file is expected to be found in /etc/sra/serverconfig.toml
# or C:\\ProgramData\\sra on Windows.

[database]
# The database section should generally be the only real editing for this 
# file.
#
# ip = "localhost"
# port = "5432"
# name = "sra"
# user = "sra"
`)

	if config["server_ip"] != "localhost" {
		fmt.Fprintln(fHandle, `ip = "`+config["server_ip"]+`"`)
	}

	if config["server_port"] != "5432" {
		fmt.Fprintln(fHandle, `port = "`+config["server_port"]+`"`)
	}

	if config["db_name"] != "sra" {
		fmt.Fprintln(fHandle, `name = "`+config["db_name"]+`"`)
	}

	if config["db_user"] != "sra" {
		fmt.Fprintln(fHandle, `user = "`+config["db_user"]+`"`)
	}

	fmt.Fprintln(fHandle, `password = "`+config["db_password"]+`"`)

	fmt.Fprint(fHandle, `# This is an Mensago server config file. Each value listed below is the 
	# default value. Every effort has been made to set this file to sensible 
	# defaults so that configuration is kept to a minimum. This file is expected
	# to be found in /etc/mensagod/serverconfig.toml or C:\\ProgramData\\mensagod
	# on Windows.
	
	[database]
	# The database section should generally be the only real editing for this 
	# file.
	#
	# ip = "localhost"
	# port = "5432"
	# name = "mensago"
	# user = "mensago"
`)

	// TODO: A lot of work to finish the setup module
}
