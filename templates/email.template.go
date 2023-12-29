package templates

import (
	"bytes"
	"strings"
	"text/template"
)

// Email contains all the templates that are related to email
type Email struct{}

// GetEmailConfirmationTmpl is a function that is used to get the email confirmation template
func (Email) GetEmailConfirmationTmpl(url string) (emailHTML string, err error) {
	emailVerification := struct{ URL string }{URL: url}

	tmpl := `
<html>
  <head>
    <style>
      .contianer {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        gap: 4;
        margin-top: 20px;
        margin-bottom: 40px;
      }
      .goto {
        align-items: center;
        background-color: #ffffff;
        border: 1px solid rgba(0, 0, 0, 0.1);
        border-radius: 0.25rem;
        box-shadow: rgba(0, 0, 0, 0.02) 0 1px 3px 0;
        box-sizing: border-box;
        color: rgba(0, 0, 0, 0.85);
        cursor: pointer;
        display: inline-flex;
        font-family: system-ui, -apple-system, system-ui, "Helvetica Neue",
          Helvetica, Arial, sans-serif;
        font-size: 16px;
        font-weight: 600;
        justify-content: center;
        line-height: 1.25;
        margin: 0;
        min-height: 3rem;
        padding: calc(0.875rem - 1px) calc(1.5rem - 1px);
        position: relative;
        text-decoration: none;
        transition: all 250ms;
        user-select: none;
        -webkit-user-select: none;
        touch-action: manipulation;
        vertical-align: baseline;
        width: auto;
      }
      .goto:hover,
      .goto:focus {
        border-color: rgba(0, 0, 0, 0.15);
        box-shadow: rgba(0, 0, 0, 0.1) 0 4px 12px;
        color: rgba(0, 0, 0, 0.65);
      }

      .goto:hover {
        transform: translateY(-1px);
      }

      .goto:active {
        background-color: #f0f0f1;
        border-color: rgba(0, 0, 0, 0.15);
        box-shadow: rgba(0, 0, 0, 0.06) 0 2px 4px;
        color: rgba(0, 0, 0, 0.65);
        transform: translateY(0);
      }
    </style>
  </head>
  <body>
    <h1>Auth Server</h1>
    <strong>Confirm your email address</strong>
    <br />
    <div class="contianer">
      <section>
        <a id="goto" class="goto" href="{{.URL}}"> Confirm Email address </a>
      </section>
    </div>
    <footer>
      If you are wondering about what this email is please ignore this email
    </footer>
  </body>
</html>
`
	t := template.Must(template.New("emailVerification").Parse(tmpl))

	var buf bytes.Buffer
	err = t.Execute(&buf, emailVerification)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}
