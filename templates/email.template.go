package templates

import (
	"bytes"
	"text/template"
)

// Email contains all the templates that are related to email
type Email struct{}

// GetEmailConfirmationTmpl is a function that is used to get the email confirmation template
func (Email) GetEmailConfirmationTmpl(url string) (emailHTML string, err error) {
	emailVerification := struct{ URL string }{URL: url}

	tmpl := `
  <h1>Authentication</h1>
  <br />
  <strong>Confirm your email address</strong>
  <br />
  <a href="{{.URL}}">Click to confirm</a>
  <br />
  <br />
  If you are wondering what is going on please ignore this email
  `
	t := template.Must(template.New("emailVerification").Parse(tmpl))

	var buf bytes.Buffer
	err = t.Execute(&buf, emailVerification)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}
