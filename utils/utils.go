// Package utils contains the utility packages
package utils

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"os"
	"strings"

	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/connect"
)

// CheckForMigrations is a function that checks wether the schema changes should be migrated to the database
func CheckForMigrations(c *connect.Connector, env *config.Env) {
	enableMigrations := flag.Bool("migrate", false, "Migrate the schema to the relational database")
	flag.Parse()
	if enableMigrations != nil && *enableMigrations {
		c.MigrateSchemaChanges(env)
		os.Exit(0)
	}
}

// GenerateChallenge is a fucntion that is used to generate a cryptographic challenge
func GenerateChallenge() (challenge *string, err error) {
	bytes := make([]byte, 32)
	_, err = rand.Read(bytes)
	if err != nil {
		return nil, err
	}

	r := strings.ReplaceAll(
		strings.ReplaceAll(
			strings.ReplaceAll(
				base64.StdEncoding.EncodeToString(bytes),
				"+", "-",
			),
			"/", "_",
		),
		"=", "",
	)
	return &r, nil
}
