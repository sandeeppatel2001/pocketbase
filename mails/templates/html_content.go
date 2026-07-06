package templates

// Available variables:
//
// ```
// HTMLContent string
// ```
const HTMLBody = `{{define "content"}}{{raw .HTMLContent}}{{end}}`
