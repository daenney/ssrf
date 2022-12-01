package main

import (
	"embed"
	"io/fs"
	"text/template"
)

const templatesDir = "templates"

var (
	//go:embed templates
	files     embed.FS
	templates map[string]*template.Template
)

func loadTemplates() error {
	if templates == nil {
		templates = make(map[string]*template.Template, 2)
	}
	tmplFiles, err := fs.ReadDir(files, templatesDir)
	if err != nil {
		return err
	}

	for _, tmpl := range tmplFiles {
		if tmpl.IsDir() {
			continue
		}

		pt, err := template.ParseFS(files, templatesDir+"/"+tmpl.Name())
		if err != nil {
			return err
		}

		templates[tmpl.Name()] = pt
	}
	return nil
}
