// Package scripts embeds the egress-boundary assets into the ovara binary so
// `ovara run --boundary` needs no files beyond the binary itself.
package scripts

import _ "embed"

//go:embed setup-egress-boundary.sh
var EgressBoundary string

//go:embed resolver.md
var ResolverDoc string
