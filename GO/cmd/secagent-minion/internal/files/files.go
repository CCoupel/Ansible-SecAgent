// Package files gère les transferts de fichiers entre le relay server et l'agent.
//
// Opérations (§11 ARCHITECTURE.md) :
//   - PutFile  : décode base64, valide le chemin, écrit sur disque, chmod
//   - FetchFile : valide le chemin, lit le fichier, retourne en base64
//
// Contraintes MVP :
//   - Taille max fichier : 500 KB (refus au-delà)
//   - Path traversal : validation des préfixes autorisés (HAUT #6)
//   - Séparation write/read paths (ALLOWED_WRITE_PREFIXES ≠ ALLOWED_READ_PREFIXES)
package files

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// MaxFileSize est la taille maximale d'un fichier transféré (500 KB MVP).
	MaxFileSize = 500 * 1024
)

// AllowedWritePrefixes est la liste des répertoires autorisés en écriture.
var AllowedWritePrefixes = []string{
	"/tmp/",
	"/var/tmp/",
	"/home/",
	"/root/",
	"/opt/",
}

// AllowedReadPrefixes est la liste des répertoires autorisés en lecture.
var AllowedReadPrefixes = []string{
	"/tmp/",
	"/var/tmp/",
	"/home/",
	"/root/",
	"/opt/",
	"/etc/",
}

// PutFileRequest décrit un transfert de fichier vers l'agent.
type PutFileRequest struct {
	TaskID string
	Dest   string // chemin de destination absolu
	DataB64 string // contenu encodé en base64
	Mode   string // ex: "0700" (défaut "0644")
}

// FetchFileRequest décrit une récupération de fichier depuis l'agent.
type FetchFileRequest struct {
	TaskID string
	Src    string // chemin source absolu
}

// PutFile valide le chemin, décode le base64 et écrit le fichier sur disque.
//
// Retourne une erreur si :
//   - Chemin hors des répertoires autorisés (PathTraversalError)
//   - Fichier décodé > 500 KB
//   - Écriture disque échoue
func PutFile(req PutFileRequest) error {
	safe, err := validatePath(req.Dest, AllowedWritePrefixes, "dest")
	if err != nil {
		return err
	}

	data, err := base64.StdEncoding.DecodeString(req.DataB64)
	if err != nil {
		// Essai RawStdEncoding (sans padding)
		data, err = base64.RawStdEncoding.DecodeString(req.DataB64)
		if err != nil {
			return fmt.Errorf("put_file: decode base64: %w", err)
		}
	}

	if len(data) > MaxFileSize {
		return fmt.Errorf("put_file: file too large (%d bytes, max %d)", len(data), MaxFileSize)
	}

	// Crée les répertoires parents si nécessaire
	parent := filepath.Dir(safe)
	if err := os.MkdirAll(parent, 0755); err != nil {
		return fmt.Errorf("put_file: mkdir %s: %w", parent, err)
	}

	if err := os.WriteFile(safe, data, 0644); err != nil {
		return fmt.Errorf("put_file: write %s: %w", safe, err)
	}

	// Applique le mode demandé
	mode := uint32(0644)
	if req.Mode != "" {
		parsed, err := strconv.ParseUint(req.Mode, 8, 32)
		if err == nil {
			mode = uint32(parsed)
		}
	}
	if err := os.Chmod(safe, os.FileMode(mode)); err != nil {
		return fmt.Errorf("put_file: chmod %s: %w", safe, err)
	}

	return nil
}

// FetchFile valide le chemin, lit le fichier et retourne son contenu en base64.
//
// Retourne une erreur si :
//   - Chemin hors des répertoires autorisés (PathTraversalError)
//   - Lecture disque échoue
func FetchFile(req FetchFileRequest) (string, error) {
	safe, err := validatePath(req.Src, AllowedReadPrefixes, "src")
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(safe)
	if err != nil {
		return "", fmt.Errorf("fetch_file: read %s: %w", safe, err)
	}

	return base64.StdEncoding.EncodeToString(data), nil
}

// PathTraversalError est retournée quand un chemin sort des répertoires autorisés.
type PathTraversalError struct {
	Path     string
	Param    string
	Resolved string
}

func (e *PathTraversalError) Error() string {
	return fmt.Sprintf("path traversal: %s=%q (resolved: %q) outside allowed prefixes", e.Param, e.Path, e.Resolved)
}

// validatePath normalise le chemin et vérifie qu'il est dans les préfixes autorisés.
//
// Utilise filepath.Clean pour résoudre ".." sans accès disque.
// Normalise vers des forward slashes pour la comparaison (compatibilité cross-platform tests).
func validatePath(path string, allowed []string, param string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("%s cannot be empty", param)
	}

	// Normalise sans accès filesystem
	norm := filepath.Clean(path)
	// Forward slashes pour comparaison (compatible tests Windows)
	normFwd := filepath.ToSlash(norm)

	for _, prefix := range allowed {
		p := strings.TrimRight(filepath.ToSlash(filepath.Clean(prefix)), "/")
		if normFwd == p || strings.HasPrefix(normFwd, p+"/") {
			return norm, nil
		}
	}

	return "", &PathTraversalError{Path: path, Param: param, Resolved: normFwd}
}

// IsPathTraversalError retourne true si l'erreur est une PathTraversalError.
func IsPathTraversalError(err error) bool {
	var e *PathTraversalError
	return errors.As(err, &e)
}
