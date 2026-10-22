package httpapi

import (
	"embed"
	"net/http"
)

//go:embed swagger_ui.html openapi.json
var docsFS embed.FS

func (s *Server) handleSwaggerUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}

	writeEmbeddedFile(w, "text/html; charset=utf-8", "swagger_ui.html")
}

func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}

	writeEmbeddedFile(w, "application/json; charset=utf-8", "openapi.json")
}

func writeEmbeddedFile(w http.ResponseWriter, contentType string, name string) {
	data, err := docsFS.ReadFile(name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
