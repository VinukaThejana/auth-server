package schemas

// BasicOAuthProvider is struct with commom feilds provided by the oauth provider
type BasicOAuthProvider struct {
	Email    *string
	ID       string
	Name     string
	Username string
}

// GitHub is a struct that contains details received from the GitHub oauth provider
type GitHub struct {
	Email     *string `json:"email"`
	Name      string  `json:"name"`
	Username  string  `json:"login"`
	AvatarURL string  `json:"avatar_url"`
	ID        int     `json:"id"`
}

// GetEmailFromPayload is a helper method on GitHub to extract the email address from the payload received from GitHub
func (g *GitHub) GetEmailFromPayload(payload map[string]interface{}) {
	if email, ok := payload["email"].(*string); ok && email != nil {
		g.Email = email
	} else {
		g.Email = nil
	}
}
