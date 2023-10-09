// Package utils contains the utility packages
package utils

import (
	"flag"
	"os"

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
