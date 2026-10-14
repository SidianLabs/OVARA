package proxy

import (
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
)

// Browser agents act through forms. What a person approving a form POST
// needs is the fields, not a wall of url-encoded text: each field by name,
// a password or a credential-shaped value masked, an uploaded file by its
// name, type and size, and the page the form was on.

const (
	multipartContentType = "multipart/form-data"
	// maxFormParse bounds the form body listed field by field; a larger one
	// is named, not listed (the body preview and hash still show it).
	maxFormParse   = 256 << 10
	maxFormSummary = 560
	maxFieldValue  = 60
	maxFormParts   = 200
	maskedValue    = "[masked]"
	undeclaredType = "undeclared type"
)

// secretFieldWords mark a field whose value is never shown.
var secretFieldWords = []string{"pass", "secret", "token", "pin", "otp", "cvv", "cvc", "card", "ssn", "credential", "auth", "private", "mfa", "2fa", "apikey", "api_key", "api-key"}

func isSecretField(name string) bool {
	n := strings.ToLower(name)
	for _, w := range secretFieldWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

// pageOf is the page a request was made from, for the person: the
// Referer (else the Origin) without its query, which can carry tokens.
func pageOf(r *http.Request) string {
	ref := r.Header.Get("Referer")
	if ref == "" {
		ref = r.Header.Get("Origin")
	}
	if ref == "" {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil || u.Host == "" {
		return truncate(redactPreview(ref), 120)
	}
	u.RawQuery, u.Fragment, u.User = "", "", nil
	return truncate(u.String(), 120)
}

// formContext adds "form" (the fields) and "uploads" (the files) to out
// for a form body, and reports how many values were masked. Not a form, or
// an encoded body: nothing is added.
func formContext(r *http.Request, hb *heldBody, out map[string]string) int {
	if hb == nil || hb.size == 0 {
		return 0
	}
	mt, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (mt != formContentType && mt != multipartContentType) {
		return 0
	}
	if len(contentEncodings(r.Header.Values("Content-Encoding"))) > 0 {
		return 0
	}
	if mt == formContentType {
		if hb.size > maxFormParse {
			out["form"] = fmt.Sprintf("form too large to list (%d bytes); see the body preview and hash", hb.size)
			return 0
		}
		data, err := io.ReadAll(hb.reader())
		if err != nil {
			return 0
		}
		return listFields(urlencodedFields(string(data)), nil, out)
	}
	boundary := params["boundary"]
	if boundary == "" {
		return 0
	}
	var fields []formField
	var uploads []string
	mr := multipart.NewReader(hb.reader(), boundary)
	for n := 0; n < maxFormParts; n++ {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		if p.FileName() != "" {
			size, _ := io.Copy(io.Discard, p)
			kind := p.Header.Get("Content-Type")
			if kind == "" {
				kind = undeclaredType
			}
			uploads = append(uploads, fmt.Sprintf("%s (%s, %d bytes)", truncate(p.FileName(), 80), truncate(kind, 40), size))
			continue
		}
		v, _ := io.ReadAll(io.LimitReader(p, 4096))
		fields = append(fields, formField{p.FormName(), string(v)})
	}
	return listFields(fields, uploads, out)
}

type formField struct{ name, value string }

// urlencodedFields reads name=value pairs in the order they were sent.
func urlencodedFields(body string) []formField {
	out := make([]formField, 0, 16)
	for _, pair := range strings.FieldsFunc(body, func(c rune) bool { return c == '&' || c == ';' }) {
		k, v, _ := strings.Cut(pair, "=")
		if kk, err := url.QueryUnescape(k); err == nil {
			k = kk
		}
		if vv, err := url.QueryUnescape(v); err == nil {
			v = vv
		}
		out = append(out, formField{k, v})
		if len(out) >= maxFormParts {
			break
		}
	}
	return out
}

func listFields(fields []formField, uploads []string, out map[string]string) int {
	masked := 0
	var b strings.Builder
	for i, f := range fields {
		v := f.value
		switch {
		case isSecretField(f.name):
			v = maskedValue
			masked++
		default:
			var n int
			v, n = redactPreviewCount(v)
			masked += n
			v = truncate(v, maxFieldValue)
		}
		entry := truncate(f.name, 40) + "=" + v
		if b.Len()+len(entry) > maxFormSummary {
			fmt.Fprintf(&b, "… (+%d more)", len(fields)-i)
			break
		}
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(entry)
	}
	if b.Len() > 0 {
		out["form"] = b.String()
	} else if len(fields) == 0 && len(uploads) == 0 {
		return 0
	}
	if len(uploads) > 0 {
		out["uploads"] = truncate(strings.Join(uploads, "; "), maxFormSummary)
	}
	return masked
}
