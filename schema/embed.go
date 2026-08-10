// Package schema exposes the authoritative protocol schemas to the reference
// relay without maintaining a second copied schema tree.
package schema

import "embed"

// FS contains the public JSON Schemas and frozen vectors exactly as shipped by
// this module.
//
//go:embed *.schema.json payloads/*.schema.json test-vectors/*.json
var FS embed.FS
