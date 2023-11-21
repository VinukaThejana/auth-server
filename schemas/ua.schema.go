package schemas

// UAOS is struct for managing UA OS details
type UAOS struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// UADevice is a struct for managing UA Device details
type UADevice struct {
	Vendor string `json:"vendor"`
	Model  string `json:"model"`
}
