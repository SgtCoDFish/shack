package shack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type CacheDir struct {
	directory string
}

func NewCacheDir(directory string) (*CacheDir, error) {
	if err := os.MkdirAll(directory, 0o775); err != nil {
		return nil, fmt.Errorf("failed to ensure dir %q exists when creating cache dir: %s", directory, err.Error())
	}

	return &CacheDir{
		directory: directory,
	}, nil
}

func (cd *CacheDir) canonicalCacheFilename(request *http.Request) string {
	// TODO: this will probably miss some opportunities for caching; can be done smarter
	return filepath.Join(cd.directory, hex.EncodeToString([]byte(requestToName(request))))
}

func (cd *CacheDir) canonicalMetadataFilename(request *http.Request) string {
	// TODO: this will probably miss some opportunities for caching; can be done smarter
	return cd.canonicalCacheFilename(request) + "_metadata.json"
}

func requestToName(request *http.Request) string {
	return request.URL.String()
}

func (cd *CacheDir) IsInCache(request *http.Request) bool {
	fileName := cd.canonicalMetadataFilename(request)

	_, err := os.Stat(fileName)

	return !os.IsNotExist(err)
}

func (cd *CacheDir) CacheEntryReader(request *http.Request) (io.ReadCloser, *CacheMetadata, error) {
	cacheFilename := cd.canonicalCacheFilename(request)

	if !cd.IsInCache(request) {
		return nil, nil, fmt.Errorf("cannot find cache entry for %s", requestToName(request))
	}

	cachedFile, err := os.Open(cacheFilename)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't open cached file %q: %w", cacheFilename, err)
	}

	// note: if we fail after here, we need to close the cached file

	metadataFilename := cd.canonicalMetadataFilename(request)

	rawCacheMetadata, err := os.ReadFile(metadataFilename)
	if err != nil {
		cachedFile.Close()
		return nil, nil, fmt.Errorf("couldn't read cache metadata file %q: %w", metadataFilename, err)
	}

	var metadata CacheMetadata

	err = json.Unmarshal(rawCacheMetadata, &metadata)
	if err != nil {
		cachedFile.Close()
		return nil, nil, fmt.Errorf("failed to parse cache metadata file %q: %w", metadataFilename, err)
	}

	return cachedFile, &metadata, nil
}

func (cd *CacheDir) CacheEntryWriter(request *http.Request, response *http.Response) (*CacheWriter, error) {
	filename := cd.canonicalCacheFilename(request)
	metadataFilename := cd.canonicalMetadataFilename(request)

	contentType := response.Header.Get("content-type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	return NewCacheWriter(filename, metadataFilename, contentType)
}

func (cd *CacheDir) Directory() string {
	return cd.directory
}

type CacheMetadata struct {
	Filename    string `json:"filename"`
	Created     string `json:"created"`
	Size        int64  `json:"size"`
	SHA256Sum   string `json:"sha256sum"`
	ContentType string `json:"contentType"`
}

type CacheWriter struct {
	filename         string
	metadataFilename string

	contentType string

	hasher hash.Hash

	file *os.File
	size int64

	created time.Time

	writer io.Writer
}

var _ io.WriteCloser = (*CacheWriter)(nil)

func NewCacheWriter(filename string, metadataFilename string, contentType string) (*CacheWriter, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}

	cw := &CacheWriter{
		filename:         filename,
		metadataFilename: metadataFilename,

		contentType: contentType,

		hasher: sha256.New(),

		file: file,
		size: 0,

		created: time.Now(),
	}

	cw.writer = io.MultiWriter(cw.hasher, cw.file)

	return cw, nil
}

func (cw *CacheWriter) Write(p []byte) (int, error) {
	written, err := cw.writer.Write(p)

	cw.size += int64(written)

	return written, err
}

func (cw *CacheWriter) Close() error {
	err := cw.file.Close()
	if err != nil {
		return err
	}

	sha256Bytes := cw.hasher.Sum(nil)

	metadata := CacheMetadata{
		Filename:    cw.filename,
		Created:     cw.created.Format(time.RFC3339),
		Size:        cw.size,
		SHA256Sum:   hex.EncodeToString(sha256Bytes),
		ContentType: cw.contentType,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	err = os.WriteFile(cw.metadataFilename, metadataBytes, 0o666)
	if err != nil {
		return err
	}

	return nil
}

func (cw *CacheWriter) Filename() string {
	return cw.filename
}
