// Package buildinfo contains software identity, independent of configuration revisions.
package buildinfo

// Override at build time with -ldflags -X veilink/internal/buildinfo.Version=...
var Version = "dev"
var Commit = "unknown"
