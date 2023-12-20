package connect

import (
	"github.com/VinukaThejana/auth/config"
	"github.com/VinukaThejana/go-utils/logger"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// InitMinioClient is a function that is used to initialize minio client
func (c *Connector) InitMinioClient(env *config.Env) {
	useSSL := config.GetDevEnv(env) != config.Dev

	client, err := minio.New(env.MinioEndpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(env.MinioAPIKeyID, env.MinioAPIKeySecret, ""),
		Secure: useSSL,
	})
	if err != nil {
		logger.Errorf(err)
	}

	c.M = client
}
