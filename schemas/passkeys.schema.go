package schemas

// PassKeyCredWhenCreating struct conatins the passkeys credentials received from the frontend when creating the passkey
type PassKeyCredWhenCreating struct {
	ClientExtensionResults  interface{} `json:"clientExtensionResults"`
	AuthenticatorAttachment interface{} `json:"authenticatorAttachment"`
	ID                      string      `json:"id"`
	Type                    string      `json:"type" validate:"required,oneof=public-key"`
	RawID                   string      `json:"rawId" validate:"required"`
	Response                struct {
		AttestationObject string        `json:"attestationObject" validate:"required"`
		ClientDataJSON    string        `json:"clientDataJSON" validate:"required"`
		Transports        []interface{} `json:"transports"`
	} `json:"response"`
}

// PassKeyCredWhenLogginIn struct contians the passkeys credentials received from the frontend while logging in
type PassKeyCredWhenLogginIn struct {
	ClientExtensionResults  interface{} `json:"clientExtensionResults"`
	AuthenticatorAttachment interface{} `json:"authenticatorAttachment"`
	ID                      string      `json:"id"`
	Type                    string      `json:"type" validate:"required,oneof=public-key"`
	RawID                   string      `json:"rawId" validate:"required"`
	Response                struct {
		AuthenticatorData string `json:"authenticatorData" validate:"required"`
		ClientDataJSON    string `json:"clientDataJSON" validate:"required"`
		Signature         string `json:"signature" validate:"required"`
		UserHandle        string `json:"userHandle" validate:"required"`
	} `json:"response"`
}

// PasskeysClientData struct contains the clientDataJSON details inside the credentials response
type PasskeysClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}
