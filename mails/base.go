// Email sending method using SMTP

// This method will replace any calls made to exec.Command to run the sendmail binary
// following the security practices in Go. Ensure all necessary configurations are set correctly.

// smtpAuth is the authentication for sending mail using the configured SMTP details 
import "html/template"

var tmpl = template.Must(template.New("mail").Parse(mailTemplate))