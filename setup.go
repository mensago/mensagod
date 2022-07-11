package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/everlastingbeta/diceware"
	"github.com/everlastingbeta/diceware/wordlist"
	"github.com/google/uuid"
	ezn "gitlab.com/darkwyrm/goeznacl"
	"gitlab.com/mensago/mensagod/dbhandler"
	"gitlab.com/mensago/mensagod/keycard"
)

// SetupConfigFile is used to obtain the necessary information from the user for creating the
// server config file
func SetupConfigFile() error {

	// Prerequisite: check for admin privileges
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

	// Step 2: Get necessary information from the user
	// - location of workspace data
	// - registration type
	// - is separate abuse account desired?
	// - is separate support account desired?
	// - quota size
	// - IP address of postgres server
	// - port of postgres server
	// - database name
	// - database username
	// - database user password
	// - required keycard fields
	config := make(map[string]string)

	var tempStr string
	var defaultDataPath = "/var/mensago"

	// location of workspace data

	programData := ""
	if runtime.GOOS == "windows" {
		for _, s := range os.Environ() {
			if strings.HasPrefix(s, "ProgramData") {
				parts := strings.Split(s, "=")
				programData = parts[1]
				break
			}
		}

		defaultDataPath = programData + "\\mensagodata"
	}

	fmt.Printf("Where should server-side user data be stored? [%s]: ", defaultDataPath)
	if len, _ := fmt.Scanln(&tempStr); len == 0 {
		tempStr = defaultDataPath
	}
	config["top_path"] = tempStr

	if _, err := os.Stat(config["top_path"]); err != nil {
		if err = os.MkdirAll(config["top_path"], os.ModePerm); err != nil {
			fmt.Printf("Unable to create directory '%s'. Error: %s\n"+
				"Please create this folder manually and rerun this command", config["config_path"],
				err.Error())
			os.Exit(1)
		}
	}

	// registration type

	fmt.Printf(`
Registration types:
  - private (default): the admin creates all accounts manually.
  - moderated: anyone can ask for an account, but the admin must approve.
  - network: anyone on a subnet can create a new account. By default this is
        set to the local network (192.168/16, 172.16/12, 10/8).
  - public: anyone with access can create a new account. Not recommended.
`)
	config["regtype"] = ""
	for config["regtype"] == "" {
		fmt.Printf("Registration mode [private]: ")
		if len, _ := fmt.Scanln(&tempStr); len == 0 {
			tempStr = "private"
		} else {
			tempStr = strings.ToLower(tempStr)
		}

		switch tempStr {
		case "private", "public", "network", "moderated":
			config["regtype"] = tempStr
		}
	}

	// certified algorithms required?

	fmt.Printf(`
---------------------------------------------------------------------------

Some organizations are under legal requirements to use certified algorithms
for encryption and signing, such as FIPS in the United States.

By answering yes to the following question, the server will prefer to use
algorithms which are certified for U.S. government use. These algorithms are
commonly certified in other countries, but you will need to check your local
laws to confirm.

By answering no, the server will use newer algorithms which are recommended
for use unless required.

In either case, this can be changed later, if needed.
`)

	config["certified_algos"] = ""
	for config["certified_algos"] == "" {
		fmt.Printf("Do you want to use certified algorithms? [y/N]: ")
		if len, _ := fmt.Scanln(&tempStr); len == 0 {
			tempStr = "n"
		} else {
			tempStr = strings.ToLower(tempStr)
		}

		switch tempStr {
		case "y", "yes":
			config["certified_algos"] = "y"
			ezn.RequireCertifiedAlgorithms(true)
		case "n", "no":
			config["certified_algos"] = "n"
		}
	}

	// are separate abuse and/or support accounts desired?

	fmt.Printf(`
Each instance has abuse and support addresses. These can autoforward
to the admin workspace or be their own separate, distinct workspaces. Smaller
environments probably will want to say "yes" here.

`)

	config["forward_abuse"] = ""
	for config["forward_abuse"] == "" {
		fmt.Printf("Do you want to autoforward abuse to admin? [Y/n]: ")
		_, _ = fmt.Scanln(&tempStr)
		tempStr = strings.ToLower(tempStr)

		switch tempStr {
		case "y", "yes", "":
			config["forward_abuse"] = "y"
		case "n", "no":
			config["forward_abuse"] = "n"
		}
	}

	config["forward_support"] = ""
	for config["forward_support"] == "" {
		fmt.Printf("Do you want to autoforward support to admin? [Y/n]: ")
		_, _ = fmt.Scanln(&tempStr)
		tempStr = strings.ToLower(tempStr)

		switch tempStr {
		case "y", "yes", "":
			config["forward_support"] = "y"
		case "n", "no":
			config["forward_support"] = "n"
		}
	}

	config["quota_size"] = ""
	fmt.Printf("\nDisk quotas set each user to a customizable default value.\n")
	for config["quota_size"] == "" {
		fmt.Printf("Size, in MiB, of default user disk quota (0 = No quota, default): ")
		if len, _ := fmt.Scanln(&tempStr); len == 0 {
			tempStr = "0"
		}

		_, err := strconv.ParseInt(tempStr, 10, 64)
		if err == nil {
			config["quota_size"] = tempStr
		}
	}

	// location of server config and log files

	if runtime.GOOS == "windows" {
		programData := ""
		for _, s := range os.Environ() {
			if strings.HasPrefix(s, "ProgramData") {
				parts := strings.Split(s, "=")
				programData = parts[1]
				break
			}
		}

		config["config_path"] = programData + "\\mensagod"
		config["log_path"] = programData + "\\mensagod"
		defaultDataPath = programData + "\\mensagod"
	} else {
		config["config_path"] = "/etc/mensagod"
		config["log_path"] = "/var/log/mensagod"
		defaultDataPath = "/var/mensagod"

		fmt.Print("Enter the name of the user to run the server as. [mensago]: ")
		if len, _ := fmt.Scanln(&tempStr); len == 0 {
			tempStr = "mensago"
		}
		config["server_user"] = tempStr

		fmt.Print("Enter the name of the group for the server user. [mensago]: ")
		if len, _ := fmt.Scanln(&tempStr); len == 0 {
			tempStr = "mensago"
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

	// IP address of postgres server

	fmt.Print("\nEnter the IP address of the database server. [localhost]: ")
	if len, _ := fmt.Scanln(&tempStr); len == 0 {
		tempStr = "localhost"
	}
	config["server_ip"] = tempStr

	// port of postgres server

	fmt.Print("Enter the database server port. [5432]: ")
	if len, _ := fmt.Scanln(&tempStr); len == 0 {
		tempStr = "5432"
	}
	config["server_port"] = tempStr

	// database and username/password

	fmt.Print("Enter the name of the database to store data. [mensago]: ")
	if len, _ := fmt.Scanln(&tempStr); len == 0 {
		tempStr = "mensago"
	}
	config["db_name"] = tempStr

	fmt.Print("Enter a username which has admin privileges on this database. [mensago]: ")
	if len, _ := fmt.Scanln(&tempStr); len == 0 {
		tempStr = "mensago"
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

	fmt.Printf(`
NOTE: Now it is time to enter the information used in the organization's
root keycard. This information can be changed, but the original information
will still be a permanent part of the organization's keycard.

Please use care when answering.
`)

	orgname_pattern := regexp.MustCompile(`\w+`)
	config["org_name"] = ""
	for config["org_name"] == "" {
		fmt.Print("Name of organization (max 64 characters): ")
		fmt.Scanln(&tempStr)
		tempStr = strings.TrimSpace(tempStr)

		if len(tempStr) > 64 && len(tempStr) < 1 {
			continue
		}

		if orgname_pattern.Match([]byte(tempStr)) {
			config["org_name"] = tempStr
		}
	}

	orgdomain_pattern := regexp.MustCompile(`([a-zA-Z0-9]+\.)+[a-zA-Z0-9]+`)
	config["org_domain"] = ""
	for config["org_domain"] == "" {
		fmt.Print("Organization's domain (max 253 characters): ")
		fmt.Scanln(&tempStr)
		tempStr = strings.TrimSpace(tempStr)

		if len(tempStr) > 253 && len(tempStr) < 3 {
			continue
		}

		if orgdomain_pattern.Match([]byte(tempStr)) {
			config["org_domain"] = tempStr
		}
	}

	fmt.Printf(`Specifying the languages used by your organization is optional.

Please use two- or three-letter language codes in order of preference from 
greatest to least and separated by a comma. You may choose up to 10 languages.

Examples: 'en' or 'fr,es'

A complete list may be found at 
https://en.wikipedia.org/wiki/List_of_ISO_639-1_codes.
`)

	language_pattern := regexp.MustCompile(`^[a-zA-Z]{2,3}(,[a-zA-Z]{2,3})*?$`)
	config["org_language"] = ""
	for config["org_language"] == "" {
		fmt.Print("Organization's domain (max 253 characters): ")
		fmt.Scanln(&tempStr)
		tempStr = strings.TrimSpace(tempStr)

		if len(strings.Split(tempStr, ",")) > 10 {
			fmt.Println("Too many languages given. Please specify no more than 10.")
			continue
		}
		if len(tempStr) > 253 {
			continue
		}

		if language_pattern.Match([]byte(tempStr)) {
			config["org_language"] = tempStr
		}
	}

	// connectivity check

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

	// Step 3: set up the database tables

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

	epair, err := ezn.GenerateEncryptionPair(ezn.PreferredAsymmetricType())
	if err != nil {
		return err
	}
	config["org_encrypt"] = epair.PublicKey.AsString()
	config["org_decrypt"] = epair.PrivateKey.AsString()

	pspair, err := ezn.GenerateSigningPair(ezn.PreferredSigningType())
	if err != nil {
		return err
	}
	config["org_verify"] = pspair.PublicKey.AsString()
	config["org_sign"] = pspair.PrivateKey.AsString()

	sspair, err := ezn.GenerateSigningPair(ezn.PreferredSigningType())
	if err != nil {
		return err
	}
	config["org_sverify"] = sspair.PublicKey.AsString()
	config["org_ssign"] = sspair.PrivateKey.AsString()

	timestamp := time.Now().UTC().Format("20060102T030405Z")

	db.Exec("INSERT INTO orgkeys(creationtime, pubkey, privkey, purpose, fingerprint) "+
		"VALUES(?1,?2,?3,?4,?5)",
		timestamp, epair.PublicKey.AsString(), epair.PrivateKey.AsString(), "encrypt",
		epair.PublicHash.AsString(),
	)

	db.Exec("INSERT INTO orgkeys(creationtime, pubkey, privkey, purpose, fingerprint) "+
		"VALUES(?1,?2,?3,?4,?5)",
		timestamp, pspair.PublicKey.AsString(), pspair.PrivateKey.AsString(), "sign",
		pspair.PublicHash.AsString(),
	)

	db.Exec("INSERT INTO orgkeys(creationtime, pubkey, privkey, purpose, fingerprint) "+
		"VALUES(?1,?2,?3,?4,?5)",
		timestamp, sspair.PublicKey.AsString(), sspair.PrivateKey.AsString(), "altsign",
		sspair.PublicHash.AsString(),
	)

	admin_wid := uuid.New().String()
	regcode, err := diceware.RollWords(6, " ", wordlist.EFFLong)
	if err != nil {
		return err
	}
	config["admin_wid"] = admin_wid
	config["admin_regcode"] = regcode

	db.Exec("INSERT INTO prereg(wid, uid, domain, regcode) VALUES(?1,?2,?3,?4)",
		admin_wid, "admin", config["org_domain"], regcode,
	)

	abuse_wid := uuid.New().String()
	regcode, err = diceware.RollWords(6, " ", wordlist.EFFLong)
	if err != nil {
		return err
	}
	config["abuse_wid"] = abuse_wid

	if config["forward_abuse"] == "y" {
		db.Exec("INSERT INTO workspaces(wid, uid, domain, wtype, status) VALUES(?1,?2,?3,?4,?5)",
			abuse_wid, "abuse", config["org_domain"], "alias", "active")
		db.Exec("INSERT INTO aliases(wid, alias) VALUES(?1,?2)",
			abuse_wid, abuse_wid+"/"+config["org_domain"])

	} else {
		db.Exec("INSERT INTO prereg(wid, uid, domain, regcode) VALUES(?1,?2,?3,?4)",
			abuse_wid, "abuse", config["org_domain"], regcode)
		db.Exec("INSERT INTO workspaces(wid, uid, domain, wtype, status) VALUES(?1,?2,?3,?4,?5)",
			abuse_wid, "abuse", config["org_domain"], "individual", "active")
	}

	support_wid := uuid.New().String()
	regcode, err = diceware.RollWords(6, " ", wordlist.EFFLong)
	if err != nil {
		return err
	}
	config["support_wid"] = support_wid

	if config["forward_support"] == "y" {
		db.Exec("INSERT INTO workspaces(wid, uid, domain, wtype, status) VALUES(?1,?2,?3,?4,?5)",
			support_wid, "support", config["org_domain"], "alias", "active")
		db.Exec("INSERT INTO aliases(wid, alias) VALUES(?1,?2)",
			support_wid, support_wid+"/"+config["org_domain"])

	} else {
		db.Exec("INSERT INTO prereg(wid, uid, domain, regcode) VALUES(?1,?2,?3,?4)",
			support_wid, "support", config["org_domain"], regcode)
		db.Exec("INSERT INTO workspaces(wid, uid, domain, wtype, status) VALUES(?1,?2,?3,?4,?5)",
			support_wid, "support", config["org_domain"], "individual", "active")
	}

	rootentry := keycard.NewOrgEntry()
	rootentry.SetFields(map[string]string{
		"Name":                       config["org_name"],
		"Primary-Verification-Key":   config["org_verify"],
		"Secondary-Verification-Key": config["org_sverify"],
		"Encryption-Key":             config["org_encrypt"],
		"Contact-Admin":              config["admin_wid"] + "/" + config["org_domain"],
	})

	if config["forward_abuse"] == "n" {
		rootentry.SetField("Contact-Abuse", config["abuse_wid"]+"/"+config["org_domain"])
	}
	if config["forward_support"] == "n" {
		rootentry.SetField("Contact-Support", config["support_wid"]+"/"+config["org_domain"])
	}
	if config["org_language"] != "" {
		rootentry.SetField("Language", config["org_language"])
	}

	if !rootentry.IsDataCompliant() {
		fmt.Printf("There was a problem with the organization data:\n%s\n",
			rootentry.MakeByteString(0))
		return errors.New("non-compliant organization data in keycard root entry")
	}

	// The preferred hash type from goeznacl changes depending on if certified algorithms are
	// required
	if err := rootentry.GenerateHash(ezn.PreferredHashType()); err != nil {
		return err
	}

	if err := rootentry.Sign(pspair.PublicKey, "Organization"); err != nil {
		fmt.Printf("There was a problem signing organization's keycard:\n")
		return err
	}

	if !rootentry.IsCompliant() {
		fmt.Printf("There was a problem with the organization's keycard:\n%s\n",
			rootentry.MakeByteString(0))
		return errors.New("non-compliant organization keycard")
	}

	db.Exec(`INSERT INTO keycards(owner, creationtime, index, entry, fingerprint)
			VALUES(?1,?2,?3,?4,?5)`,
		"organization", rootentry.Fields["Timestamp"], rootentry.Fields["Index"],
		string(rootentry.MakeByteString(0)), rootentry.Hash)

	// Now that we have all the information we need from the user and the database is ready for us,
	// configure the system and create the server config file.

	// For POSIX platforms, ensure that the user and group for the server daemon exist
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
					"Please create the group manually as a system group and rerun this command",
					config["server_group"], output)
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
					"Please create the user manually as a system user without a login shell "+
					"and rerun this command", config["server_user"], output)
				os.Exit(1)
			}
		}
	}

	// create the server config folder and, for POSIX platforms, the log folder

	if _, err := os.Stat(config["config_path"]); err != nil {
		if err = os.MkdirAll(config["config_path"], os.ModePerm); err != nil {
			fmt.Printf("Unable to create directory '%s'. Error: %s\n"+
				"Please create this folder manually and rerun this command", config["config_path"],
				err.Error())
			os.Exit(1)
		}
	}

	if _, err := os.Stat(config["log_path"]); err != nil {
		if err = os.MkdirAll(config["log_path"], os.ModePerm); err != nil {
			fmt.Printf("Unable to create directory '%s'. Error: %s\n"+
				"Please create this folder manually and rerun this command", config["log_path"],
				err.Error())
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
				"Please set the group to %s and rerun this command.\n"+
				"Error: %s", config["log_path"], config["server_group"], err.Error())
			os.Exit(2)
		}
	}

	// Step 4: save the config file

	configFilePath := filepath.Join(config["config_path"], "serverconfig.toml")
	if _, err := os.Stat(configFilePath); err == nil {
		backupName := fmt.Sprintf("serverconfig.toml.%s", time.Now().Format("20060102T150405Z"))
		fmt.Printf("Config file %s exists. Renaming to %s\n", configFilePath, backupName)
		err := os.Rename(configFilePath, filepath.Join(configFilePath, backupName))
		if err != nil {
			fmt.Println("Error backing up the server config file: " + err.Error())
			fmt.Println("Please resolve this and re-run this command.")
			os.Exit(1)
		}
	}

	fHandle, err := os.Create(configFilePath)
	if err != nil {
		fmt.Println("Error creating the server config file: " + err.Error())
		fmt.Println("Please resolve this and re-run this command.")
		os.Exit(1)
	}
	defer fHandle.Close()

	fHandle.WriteString(`# This is a Mensago server config file. Each value listed below is the
# default value. Every effort has been made to set this file to sensible
# defaults to keep things simple. This file is expected to be found in
# /etc/mensagod/serverconfig.toml or C:\ProgramData\mensagod on Windows.

[database]
# The database section should generally be the only real editing for this
# file.
#
# ip = "localhost"
# port = "5432"
# name = "mensago"
# user = "mensago"
`)

	if config["server_ip"] != "localhost" {
		fmt.Fprintln(fHandle, `ip = "`+config["server_ip"]+`"`)
	}

	if config["server_port"] != "5432" {
		fmt.Fprintln(fHandle, `port = "`+config["server_port"]+`"`)
	}

	if config["db_name"] != "mensago" {
		fmt.Fprintln(fHandle, `name = "`+config["db_name"]+`"`)
	}

	if config["db_user"] != "mensago" {
		fmt.Fprintln(fHandle, `user = "`+config["db_user"]+`"`)
	}

	fmt.Fprintln(fHandle, `password = "`+config["db_password"]+`"`)

	fHandle.WriteString(`
# The location where user data is stored. The default for Windows is 
# "C:\ProgramData\mensago", but for other platforms is "/var/mensago".
`)
	// Make sure that the commented-out line is correct for the platform
	if runtime.GOOS != "windows" {
		fHandle.WriteString(`# top_dir = "C:\ProgramData\mensago"` + "\n")
	} else {
		fHandle.WriteString(`# top_dir = "/var/mensago"` + "\n")
	}

	if config["top_path"] != defaultDataPath {
		fmt.Fprintln(fHandle, `top_dir = "`+config["top_dir"]+`"`)
	}

	fHandle.WriteString(`
# The type of registration. 'public' is open to outside registration requests,
# and would be appropriate only for hosting a public free server. 'moderated'
# is open to public registration, but an administrator must approve the request
# before an account can be created. 'network' limits registration to a 
# specified subnet or IP address. 'private' permits account registration only
# by an administrator. For most situations 'private' is the appropriate setting.
# registration = "private"
`)

	if config["regtype"] != "private" {
		fmt.Fprintln(fHandle, `regtype = "`+config["regtype"]+`"`)
	}

	fHandle.WriteString(`
# For servers configured to network registration, this variable sets the 
# subnet(s) to which account registration is limited. Subnets are expected to
# be in CIDR notation and comma-separated. The default setting restricts
# registration to the private (non-routable) networks.
# registration_subnet = "192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8, 127.0.0.1/8"
# registration_subnet6 = "fe80::/10"
# 
# The default storage quota for a workspace, measured in MiB. 0 means no limit.
# default_quota = 0
`)

	if config["quota_size"] != "0" {
		fmt.Fprintln(fHandle, `quota_size = "`+config["quota_size"]+`"`)
	}

	fHandle.WriteString(`
# Location for log files. This directory requires full permissions for the
# user mensagod runs as. On Windows, this defaults to the same location as the
# server config file, i.e. C:\ProgramData\mensagod
# log_path = "/var/log/mensagod"
`)
	if runtime.GOOS != "windows" {
		fHandle.WriteString(`# log_path = "` + config["config_path"] + `"` + "\n")
	} else {
		fHandle.WriteString(`# top_dir = "/var/mensago"` + "\n")
	}

	fHandle.WriteString(`
[network]
# The interface and port to listen on
# listen_ip = "127.0.0.1"
# port = "2001"

[performance]
# Items in this section are for performance tuning. They are set to defaults
# which should work for most environments. Care should be used when changing
# any of these values.
# 
# The maximum size in MiB of a file stored on the server. Note that this is 
# the size of the actual data stored on disk. Encoding adds 25% overhead.
# max_file_size = 50
#
# The maximum size in MiB of a message. The value of max_file_size takes 
# precedence if this value is larger than the value of max_file_size.
# max_message_size = 50
#
# Max age of sync records in days. Any records older than the oldest device 
# login timestamp minus this number of days are purged. Defaults to 1 week,
# which should be plenty.
#
# performance.max_sync_age = 7
#
# The maximum number of worker threads created handle delivering messages,
# both internally and externally
#
# performance.max_delivery_threads = 100
#
# The maximum number of client worker threads. Be careful in changing this
# number -- if it is too low, client devices many not be able to connect
# and messages may not be delivered from outside the organization, and if it
# is set too high, client demand may overwhelm the server.
#
# performance.max_client_threads = 10000
#
# The maximum number of keycards to keep in the in-memory cache. This number
# has a direct effect on the server's memory usage, so adjust this with care.
# performance.keycard_cache_size = 5000

[security]
# The Diceware passphrase method is used to generate preregistration and
# password reset codes. Four word lists are available for use:
# 
# 'eff_long' - List from the Electronic Frontier Foundation of long words.
# 'eff_short' - The EFF's short word list.
# 'eff_short_prefix' - Another short word list from the EFF with some features
                       that make typing easier and offer a little more
                       security over eff_short.
# 'original' - Arnold Reinhold's original Diceware word list. Not recommended
#              for most situations.
#
# The EFF's rationale for these word lists can be found at 
# https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases
#
# For more information about Diceware, visit
# https://theworld.com/~reinhold/diceware.html
# diceware_wordlist = "eff_short_prefix"
#
# The number of words used in a Diceware code. 6 is recommended for best
# security in most situations. This value cannot be less than 3.
# diceware_wordcount = 6
#
# The number of seconds to wait after a login failure before accepting another
# attempt
# failure_delay_sec = 3
# 
# The number of login failures made before a connection is closed. 
# max_failures = 5
# 
# The number of minutes the client must wait after reaching max_failures
# before another attempt may be made. Note that additional attempts to login
# prior to the completion of this delay resets the timeout.
# lockout_delay_min = 15
# 
# The delay, in minutes, between account registration requests from the same
# IP address. This is to prevent registration spam.
# registration_delay_min = 15
# 
# The amount of time, in minutes, a password reset code is valid. It must be
# at least 10 and no more than 2880 (48 hours).
# password_reset_min = 60
# 
# Are certified algorithms required?
# certified_algorithms = n
`)

	if config["certified_algos"] == "y" {
		fmt.Fprintln(fHandle, `certified_algorithms = "y"`)
	}

	fmt.Printf(`

==============================================================================
Basic setup is complete.

From here, please make sure you:
		
`)
	fmt.Printf("1) Review the config file at %s", config["config_path"])

	fmt.Printf(`
2) Make sure port 2001 is open on the firewall.
3) Start the mensagod service.
4) Finish registration of the admin account on a device that is NOT this server.
5) If you are using separate abuse or support accounts, also complete
   registration for those accounts on a device that is NOT this server.
`)

	fmt.Printf("Administrator workspace: %s/%s\n", config["admin_wid"], config["org_domain"])
	fmt.Printf("Administrator registration code: %s\n\n", config["admin_regcode"])

	if config["foward_abuse"] != "y" {
		fmt.Printf("Abuse workspace: %s/%s\n", config["abuse_wid"], config["org_domain"])
		fmt.Printf("Abuse registration code: %s\n\n", config["abuse_regcode"])
	}

	if config["foward_support"] != "y" {
		fmt.Printf("Support workspace: %s/%s\n", config["support_wid"], config["org_domain"])
		fmt.Printf("Support registration code: %s\n\n", config["support_regcode"])
	}

	return nil
}
