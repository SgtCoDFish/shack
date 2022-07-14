package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jetstack/shack"
)

var (
	address = flag.String("address", "[::1]", "address on which to bind")
	port    = flag.Int("port", 18121, "port on which to listen")

	tlsChainFile = flag.String("tls-chain", "", "file containing TLS chain")
	tlsKeyFile   = flag.String("tls-key", "", "file containing TLS private key")

	cacheDir = flag.String("cache-dir", "/tmp/shack-cache", "directory in which to cache responses")
)

// These headers shouldn't be set on a request to upstream
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopByHopHeaders(header http.Header) {
	for _, h := range hopByHopHeaders {
		header.Del(h)
	}
}

type proxyServer struct {
	logger *log.Logger

	cache *shack.CacheDir
}

// manualWriteHTTPResponse writes a plaintext HTTP response to the given connection; this is useful after an HTTP connection
// has been hijacked leaving http.ResponseWriter unusable
func manualWriteHTTPResponse(c net.Conn, req *http.Request, statusCode int, body io.Reader) error {
	return manualWriteHTTPResponseWithMetadata(c, req, statusCode, body, nil)
}

// manualWriteHTTPResponseWithMetadata writes an HTTP response to the given connection with headers adjusted by the given metadata;
// this is useful after an HTTP connection has been hijacked leaving http.ResponseWriter unusable
func manualWriteHTTPResponseWithMetadata(c net.Conn, req *http.Request, statusCode int, body io.Reader, metadata *shack.CacheMetadata) error {
	resp := &http.Response{
		StatusCode: statusCode,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Request:    req,
		Header:     make(http.Header),
	}

	resp.Header.Set("content-type", "text/plain")

	if metadata != nil {
		if metadata.ContentType != "" {
			resp.Header.Set("content-type", metadata.ContentType)
		}
	}

	if body != nil {
		if rcBody, ok := body.(io.ReadCloser); ok {
			resp.Body = rcBody
		} else {
			resp.Body = io.NopCloser(body)
		}
	}

	err := resp.Write(c)
	if err != nil {
		return err
	}

	return nil
}

func logErrorIfNeeded(logger *log.Logger, msg string, err error) {
	if err != nil {
		logger.Printf("%s: %s", msg, err.Error())
	}
}

func (p *proxyServer) handleConnect(hijackableWriter http.ResponseWriter, originalRequest *http.Request) {
	p.logger.Printf("proxying %q", originalRequest.Host)

	hijacker, ok := hijackableWriter.(http.Hijacker)
	if !ok {
		p.logger.Printf("failed to hijack http.ResponseWriter; this is likely a programmer error", originalRequest.Host)
		http.Error(hijackableWriter, "failed to hijack HTTP connection", http.StatusInternalServerError)
		return
	}

	clientConnection, bufferedData, err := hijacker.Hijack()
	if err != nil {
		// presumably if we get here we can still use `hijackableWriter` to write an error since we didn't successfully hijack
		p.logger.Printf("failed to hijack an HTTP connection to %s; this is likely a programmer error", originalRequest.Host)
		http.Error(hijackableWriter, "failed to hijack HTTP connection", http.StatusInternalServerError)
		return
	}

	defer clientConnection.Close()

	// from here we can no longer use hijackableWriter to write a response

	if bufferedData.Reader.Buffered() > 0 {
		// in testing with curl there doesn't seem to be anything stored in here, but it's worth warning if
		// we do find anything, because the bytes we expect after the CONNECT request should be the beginning of a TLS handshake
		p.logger.Printf("warning: bufferedData has %d bytes buffered; upcoming TLS handshake might fail", bufferedData.Reader.Buffered())

	}

	// send a 200 OK response to the client to indicate that we're ready to "proxy" the connection
	if err := manualWriteHTTPResponse(clientConnection, originalRequest, 200, nil); err != nil {
		p.logger.Printf("failed to write CONNECT OK response: %s", err.Error())
		return
	}

	// after we've returned a 200 OK, we expect the client to try a TLS handshake to the upstream server;
	// this is what we want to intercept

	tlsServerConn := tls.Server(clientConnection, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// TODO: get cert based on hello.ServerName

			tlsCert, err := tls.LoadX509KeyPair(*tlsChainFile, *tlsKeyFile)
			if err != nil {
				return nil, err
			}

			return &tlsCert, nil
		},
	})

	if err := tlsServerConn.Handshake(); err != nil {
		p.logger.Printf("failed to complete TLS handshake with client: %s", err.Error())

		// difficult to return much of an error here; we failed during a TLS handshake and so HTTP errors
		// might not be any use since the client hasn't even managed to connect
		// just die and hope the TLS error the client received was good enough
		return
	}

	p.logger.Printf("successfully MitM'd connection to %q", originalRequest.Host)

	originalMitmRequest, err := http.ReadRequest(bufio.NewReader(tlsServerConn))
	if err != nil {
		p.logger.Printf("failed to parse HTTP request from client: %s", err.Error())

		// if the client didn't send an HTTP request to us, we can't return a sensible error because they
		// might not be expecting an HTTP response
		return
	}

	mitmRequest := originalMitmRequest.Clone(context.Background())

	mitmRequest.RequestURI = ""
	mitmRequest.URL.Scheme = "https"
	mitmRequest.URL.Host = mitmRequest.Host
	removeHopByHopHeaders(mitmRequest.Header)

	if p.cache.IsInCache(mitmRequest) {
		p.logger.Printf("request is cached, returning cached body")

		cacheEntry, cacheEntryMetadata, err := p.cache.CacheEntryReader(mitmRequest)
		if err != nil {
			p.logger.Printf("failed open file in cache: %s", err.Error())
			return
		}

		defer cacheEntry.Close()

		err = manualWriteHTTPResponseWithMetadata(tlsServerConn, mitmRequest, 200, cacheEntry, cacheEntryMetadata)
		if err != nil {
			p.logger.Printf("failed to write HTTP response with body from cache")
			// no point trying to write a further error via HTTP if we couldn't write this response
		}

		return
	}

	p.logger.Printf("making proxy request to %s", mitmRequest.URL.String())

	httpClient := &http.Client{
		Timeout: 1 * time.Minute,
	}

	upstreamResponse, err := httpClient.Do(mitmRequest)

	if err != nil {
		p.logger.Printf("failed to request upstream: %s", err.Error())

		responseError := manualWriteHTTPResponse(tlsServerConn, originalMitmRequest, http.StatusBadGateway, bytes.NewBufferString("failed to make request to upstream server"))

		logErrorIfNeeded(p.logger, "failed to write error response to client after failed request upstream", responseError)
		return
	}

	defer upstreamResponse.Body.Close()

	// TODO: should only cache if the HTTP deaers on the response from upstream allow it

	cacheWriter, err := p.cache.CacheEntryWriter(mitmRequest, upstreamResponse)
	if err != nil {
		// TODO: could probably just return the body without caching as a less disruptive option here, but for now we'll error out
		p.logger.Printf("failed to open file in cache directory: %s", err.Error())

		responseError := manualWriteHTTPResponse(tlsServerConn, originalMitmRequest, http.StatusBadGateway, bytes.NewBufferString("shack: failed to write to cache"))
		logErrorIfNeeded(p.logger, "failed to write error response to client after failed request upstream", responseError)

		return
	}

	p.logger.Printf("writing new cache entry for %q at path %s", mitmRequest.URL.String(), cacheWriter.Filename())

	// TODO: it should be possible to write to the cache and the HTTP response body at the same time
	_, err = io.Copy(cacheWriter, upstreamResponse.Body)
	if err != nil {
		_ = cacheWriter.Close()
		p.logger.Printf("failed to write to cache file before finalizing: %s", err.Error())

		responseError := manualWriteHTTPResponse(tlsServerConn, originalMitmRequest, http.StatusBadGateway, bytes.NewBufferString("shack: failed to write to cache"))
		logErrorIfNeeded(p.logger, "failed to write error response to client after failed attempt to write to cache", responseError)

		return
	}

	err = cacheWriter.Close()
	if err != nil {
		p.logger.Printf("failed to close cache entry / metadata: %s", err.Error())

		// this is fatal since we already consumed the response Body

		responseError := manualWriteHTTPResponse(tlsServerConn, originalMitmRequest, http.StatusBadGateway, bytes.NewBufferString("shack: failed to write to cache"))
		logErrorIfNeeded(p.logger, "failed to write error response to client after failed attempt to close cache entry", responseError)

		return
	}

	p.logger.Printf("wrote cache entry for %q", mitmRequest.URL.String())

	// should now be able to read the file from the cache, and send it to the client

	cacheEntry, cacheEntryMetadata, err := p.cache.CacheEntryReader(mitmRequest)
	if err != nil {
		p.logger.Printf("failed open file in cache: %s", err.Error())
		return
	}

	defer cacheEntry.Close()

	err = manualWriteHTTPResponseWithMetadata(tlsServerConn, originalMitmRequest, upstreamResponse.StatusCode, cacheEntry, cacheEntryMetadata)
	if err != nil {
		p.logger.Printf("failed to write HTTP response with body from upstream")

		// no point trying to write a further error via HTTP if we couldn't write this response
		return
	}
}

func (p *proxyServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == "CONNECT" {
		// the real magic happens in handleConnect; the standards require that for proxying HTTPS
		// the client must first send a CONNECT request to the server, which will then establish
		// a tunnel and forward the bytes onwards

		// that means under normal operation we only expect "CONNECT" requests
		p.handleConnect(w, req)
		return
	}

	// respond to non-CONNECT requests as a health check; this doesn't do any interception, it's just a regular server
	_, err := w.Write([]byte("you connected to shack but haven't used CONNECT to establish a tunnel; the server is up, now use it!\n"))
	if err != nil {
		p.logger.Printf("failed to write generic HTTP response: %s", err.Error())
		http.Error(w, "failed to write generic unproxied response", http.StatusInternalServerError)
		return
	}
}

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds|log.LUTC)

	flag.Parse()

	cache, err := shack.NewCacheDir(*cacheDir)
	if err != nil {
		logger.Fatalf("couldn't ensure cache dir: %s", err.Error())
	}

	logger.Printf("caching in %q", cache.Directory())

	address := fmt.Sprintf("%s:%d", *address, *port)

	listener, err := net.Listen("tcp", address)
	if err != nil {
		logger.Fatalf("failed to create TCP listener on %s: %s", address, err.Error())
	}

	logger.Printf("listening on %s", address)

	server := &http.Server{
		ErrorLog: logger,

		Handler: &proxyServer{
			cache:  cache,
			logger: logger,
		},

		// set TLSNextProto to an empty map, which disables HTTP/2
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, syscall.SIGINT)

	go func() {
		var err error

		if *tlsChainFile != "" && *tlsKeyFile != "" {
			err = server.ServeTLS(listener, *tlsChainFile, *tlsKeyFile)
		} else {
			err = server.Serve(listener)
		}

		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("failed to listen: %s", err.Error())
		}
	}()

	<-sigs
	log.Println("shutting down server")

	err = server.Shutdown(context.Background())
	if err != nil {
		log.Fatalf("failed to shut down server: %s", err.Error())
	}
}
