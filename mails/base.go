// Package mails implements various helper methods for sending common
// emails like forgotten password, verification, etc.
package mails

import (
	"bytes"
	"html/template"
)

// resolveTemplateContent resolves inline html template strings.
func resolveTemplateContent(data any, content ...string) (string, error) {
	if len(content) == 0 {
		return "", nil
	}

	t := template.New("inline_template").Funcs(template.FuncMap{
		"raw": func(str string) template.HTML {
			return template.HTML(str)
		},
	})

	var parseErr error
	for _, v := range content {
		t, parseErr = t.Parse(v)
		if parseErr != nil {
			return "", parseErr
		}
	}

	var wr bytes.Buffer

	if executeErr := t.Execute(&wr, data); executeErr != nil {
		return "", executeErr
	}

	return wr.String(), nil
}
