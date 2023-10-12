package connect

import (
	"fmt"
	"os"

	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/auth/models"
	"github.com/VinukaThejana/go-utils/logger"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

// InitDatabase is a fucntion to initialize the connection with the postgres database
func (c *Connector) InitDatabase(env *config.Env) {
	db, err := gorm.Open(postgres.Open(env.DSN), &gorm.Config{})
	if err != nil {
		logger.Errorf(err)
	}

	if config.GetDevEnv(env) != config.Prod {
		db.Logger = gormLogger.Default.LogMode(gormLogger.Info)
	}

	c.DB = db
}

// MigrateSchemaChanges is a fucntion that is used to migrate schema changes to the database
func (c *Connector) MigrateSchemaChanges(env *config.Env) {
	if config.GetDevEnv(env) == config.Prod {
		logger.Error(fmt.Errorf(" 🪨 Cannot migrate schema changes on production !"))
		os.Exit(0)
	}

	migrations := []interface{}{
		models.User{},
		models.OTP{},
		models.OAuth{},
	}
	if len(migrations) == 0 {
		logger.Error(fmt.Errorf(" ❌ No items to migrate ! "))
		os.Exit(0)
	}

	c.DB.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"")

	err := c.DB.AutoMigrate(migrations...)
	if err != nil {
		logger.Errorf(err)
	}

	logger.Log("\n\n ✅ All schema changes have been migrated !")
}
