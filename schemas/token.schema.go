package schemas

// RefreshTokenDetails is a function that is used to store refresh token related data
type RefreshTokenDetails struct {
	UserID          string
	AccessTokenUUID string
}

// RefreshTokenMetadata is a struct that contains details of the device that created the refresh token
type RefreshTokenMetadata struct {
	IPAddress    string
	City         string
	Country      string
	Query        string
	RegionName   string
	Timezone     string
	Zip          string
	DeviceVendor string
	DeviceModel  string
	OSName       string
	OSVersion    string
	MapsURL      string
	Lat          float32
	Lon          float32
}
