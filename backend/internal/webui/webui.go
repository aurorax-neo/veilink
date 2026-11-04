// Package webui embeds the management Web build into the veilink executable.
//
// The release pipeline builds frontend/ directly into dist/ before go build.
// The committed dist/index.html is only a placeholder so plain go build and
// go test work in a fresh checkout.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var files embed.FS

// FS returns the embedded Web root (the contents of dist/).
func FS() fs.FS {
	sub, err := fs.Sub(files, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
