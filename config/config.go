// Package config config contains configurations
package config

// DevEnv contains production and development enviroments
type DevEnv string

const (
	// Prod defines the production enviroment
	Prod DevEnv = "PROD"
	// Dev defines the development enviroment
	Dev DevEnv = "DEV"
	// Test defined the development enviroment
	Test DevEnv = "TEST"
)

// GetDevEnv is a function to get the development enviroment based
// on the enviroment configuration
func GetDevEnv(env *Env) DevEnv {
	switch env.DevEnv {
	case string(Prod):
		return Prod
	case string(Dev):
		return Dev
	default:
		return Test
	}
}
