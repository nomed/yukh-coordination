// Package schema exposes the authoritative protocol schemas to the reference
// relay without maintaining a second copied schema tree.
package schema

import "embed"

// FS contains the public v0.1 JSON Schemas exactly as shipped by this module.
//
//go:embed *.schema.json payloads/*.schema.json
var FS embed.FS
