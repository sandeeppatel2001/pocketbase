// Package template is a thin wrapper around the standard html/template
// and text/template packages that implements a convenient registry to
// load and cache templates on the fly concurrently.
//
// It was created to assist the JSVM plugin HTML rendering, but could be used in other Go code.
//
// Example:
//
//	registry := template.NewRegistry()
//
//	html1, err := registry.LoadFiles(
//		// the files set wil be parsed only once and then cached
//		"layout.html",
//		"content.html",
//	).Render(map[string]any{"name": "John"})
//
//	html2, err := registry.LoadFiles(
//		// reuse the already parsed and cached files set
//		"layout.html",
//		"content.html",
//	).Render(map[string]any{"name": "Jane"})
package template

import (
	"fmt"
	"html"
	"html/template"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/pocketbase/pocketbase/tools/store"
	xhtml "golang.org/x/net/html"
)

// NewRegistry creates and initializes a new templates registry with
// some defaults (eg. global "raw" template function for HTML).
//
// Use the Registry.Load* methods to load templates into the registry.
func NewRegistry() *Registry {
	return &Registry{
		cache: store.New[string, *Renderer](nil),
		funcs: template.FuncMap{
			"raw": func(str string) template.HTML {
				return template.HTML(sanitizeHTML(str))
			},
		},
	}
}

// Registry defines a templates registry that is safe to be used by multiple goroutines.
//
// Use the Registry.Load* methods to load templates into the registry.
type Registry struct {
	cache *store.Store[string, *Renderer]
	funcs template.FuncMap
}

// AddFuncs registers new global template functions.
//
// The key of each map entry is the function name that will be used in the templates.
// If a function with the map entry name already exists it will be replaced with the new one.
//
// The value of each map entry is a function that must have either a
// single return value, or two return values of which the second has type error.
//
// Example:
//
//	r.AddFuncs(map[string]any{
//	  "toUpper": func(str string) string {
//	      return strings.ToUppser(str)
//	  },
//	  ...
//	})
func (r *Registry) AddFuncs(funcs map[string]any) *Registry {
	for name, f := range funcs {
		r.funcs[name] = f
	}

	return r
}

// LoadFiles caches (if not already) the specified filenames set as a
// single template and returns a ready to use Renderer instance.
//
// There must be at least 1 filename specified.
func (r *Registry) LoadFiles(filenames ...string) *Renderer {
	key := strings.Join(filenames, ",")

	found := r.cache.Get(key)

	if found == nil {
		// parse and cache
		tpl, err := template.New(filepath.Base(filenames[0])).Funcs(r.funcs).ParseFiles(filenames...)
		found = &Renderer{template: tpl, parseError: err}
		r.cache.Set(key, found)
	}

	return found
}

// LoadString caches (if not already) the specified inline string as a
// single template and returns a ready to use Renderer instance.
func (r *Registry) LoadString(text string) *Renderer {
	found := r.cache.Get(text)

	if found == nil {
		// parse and cache (using the text as key)
		tpl, err := template.New("").Funcs(r.funcs).Parse(text)
		found = &Renderer{template: tpl, parseError: err}
		r.cache.Set(text, found)
	}

	return found
}

// LoadFS caches (if not already) the specified fs and globPatterns
// pair as single template and returns a ready to use Renderer instance.
//
// There must be at least 1 file matching the provided globPattern(s)
// (note that most file names serves as glob patterns matching themselves).
func (r *Registry) LoadFS(fsys fs.FS, globPatterns ...string) *Renderer {
	key := fmt.Sprintf("%v%v", fsys, globPatterns)

	found := r.cache.Get(key)

	if found == nil {
		// find the first file to use as template name (it is required when specifying Funcs)
		var firstFilename string
		if len(globPatterns) > 0 {
			list, _ := fs.Glob(fsys, globPatterns[0])
			if len(list) > 0 {
				firstFilename = filepath.Base(list[0])
			}
		}

		tpl, err := template.New(firstFilename).Funcs(r.funcs).ParseFS(fsys, globPatterns...)
		found = &Renderer{template: tpl, parseError: err}
		r.cache.Set(key, found)
	}

	return found
}

var safeElements = map[string]bool{
	"a": true, "abbr": true, "b": true, "blockquote": true,
	"br": true, "caption": true, "cite": true, "code": true,
	"col": true, "colgroup": true, "dd": true, "del": true,
	"details": true, "dfn": true, "div": true, "dl": true,
	"dt": true, "em": true, "figcaption": true, "figure": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true,
	"h6": true, "hr": true, "i": true, "img": true, "ins": true,
	"kbd": true, "li": true, "mark": true, "ol": true, "p": true,
	"pre": true, "q": true, "s": true, "samp": true, "small": true,
	"span": true, "strong": true, "sub": true, "summary": true,
	"sup": true, "table": true, "tbody": true, "td": true,
	"tfoot": true, "th": true, "thead": true, "time": true,
	"tr": true, "u": true, "ul": true, "var": true,
}

var voidElements = map[string]bool{
	"br": true, "hr": true, "img": true,
}

var safeURLSchemes = map[string]bool{
	"http": true, "https": true, "mailto": true, "tel": true, "ftp": true,
}

func isSafeURL(url string) bool {
	url = strings.TrimSpace(url)
	if url == "" {
		return true
	}

	if url[0] == '/' || url[0] == '#' || url[0] == '.' {
		return true
	}

	schemeEnd := strings.Index(url, ":")
	if schemeEnd == -1 {
		return true
	}

	scheme := strings.ToLower(url[:schemeEnd])

	return safeURLSchemes[scheme]
}

func isSafeAttr(tag string, attr xhtml.Attribute) bool {
	key := strings.ToLower(attr.Key)

	if strings.HasPrefix(key, "on") {
		return false
	}

	switch key {
	case "style", "srcdoc", "sandbox", "formaction", "formenctype",
		"formmethod", "formnovalidate", "formtarget":
		return false
	}

	switch key {
	case "action", "cite", "data", "href", "longdesc", "poster", "src":
		return isSafeURL(attr.Val)
	}

	switch key {
	case "class", "dir", "hidden", "id", "lang", "title":
		return true
	}

	switch tag {
	case "a":
		switch key {
		case "download", "hreflang", "rel", "target", "type":
			return true
		}
	case "img":
		switch key {
		case "alt", "crossorigin", "decoding", "height", "loading",
			"referrerpolicy", "sizes", "srcset", "width":
			return true
		}
	case "td", "th":
		switch key {
		case "abbr", "colspan", "headers", "rowspan", "scope":
			return true
		}
	case "col", "colgroup":
		switch key {
		case "span":
			return true
		}
	case "time":
		switch key {
		case "datetime":
			return true
		}
	case "ol":
		switch key {
		case "reversed", "start", "type":
			return true
		}
	case "li":
		switch key {
		case "value":
			return true
		}
	case "del", "ins":
		switch key {
		case "cite", "datetime":
			return true
		}
	case "blockquote", "q":
		switch key {
		case "cite":
			return true
		}
	case "details":
		switch key {
		case "open":
			return true
		}
	}

	return false
}

func renderSafeHTML(buf *strings.Builder, n *xhtml.Node) {
	switch n.Type {
	case xhtml.TextNode:
		buf.WriteString(html.EscapeString(n.Data))
	case xhtml.ElementNode:
		if !safeElements[n.Data] {
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				renderSafeHTML(buf, c)
			}
			return
		}

		buf.WriteByte('<')
		buf.WriteString(n.Data)
		for _, attr := range n.Attr {
			if !isSafeAttr(n.Data, attr) {
				continue
			}
			buf.WriteByte(' ')
			buf.WriteString(attr.Key)
			buf.WriteString(`="`)
			buf.WriteString(html.EscapeString(attr.Val))
			buf.WriteByte('"')
		}
		buf.WriteByte('>')

		if voidElements[n.Data] {
			return
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			renderSafeHTML(buf, c)
		}

		buf.WriteString("</")
		buf.WriteString(n.Data)
		buf.WriteByte('>')
	case xhtml.DocumentNode:
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			renderSafeHTML(buf, c)
		}
	}
}

// sanitizeHTML strips all unsafe HTML tags and attributes,
// allowing only a safe subset of HTML elements with validated attributes.
func sanitizeHTML(input string) string {
	doc, err := xhtml.Parse(strings.NewReader(input))
	if err != nil {
		return html.EscapeString(input)
	}

	var buf strings.Builder
	renderSafeHTML(&buf, doc)

	return buf.String()
}
