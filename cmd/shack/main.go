package main

import (
	"bufio"
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
)

var (
	address = flag.String("address", "[::1]", "address on which to bind")
	port    = flag.Int("port", 18121, "port on which to listen")

	tlsChainFile = flag.String("tls-chain", "", "file containing TLS chain")
	tlsKeyFile   = flag.String("tls-key", "", "file containing TLS private key")
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
}

func (p *proxyServer) handleConnect(w http.ResponseWriter, req *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.logger.Printf("failed to hijack an http connection to %s; this is likely a programmer error", req.Host)
		http.Error(w, "failed to hiack HTTP connection", http.StatusInternalServerError)
		return
	}

	clientConnection, bufferedData, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	defer clientConnection.Close()

	if bufferedData.Reader.Buffered() > 0 {
		p.logger.Printf("warning: bufferedData has %d bytes buffered\n", bufferedData.Reader.Buffered())

	}

	connectOKResponse := &http.Response{
		StatusCode: 200,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Request:    req,
	}

	err = connectOKResponse.Write(clientConnection)
	if err != nil {
		p.logger.Printf("failed to write CONNECT OK response: %s", err.Error())
		return
	}

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
		// TODO: return some client error
		// http.Error(w, "failed to complete hijacked TLS handshake", http.StatusInternalServerError)
		return
	}

	p.logger.Printf("successfully MitM'd connection to %s", req.Host)

	clientRequest := bufio.NewReader(tlsServerConn)

	mitmRequest, err := http.ReadRequest(clientRequest)
	if err != nil {
		p.logger.Printf("failed to parse HTTP request from client: %s", err.Error())
		return
	}

	p.logger.Printf("host: %s | URI: %s", mitmRequest.Host, mitmRequest.RequestURI)
}

func (p *proxyServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	p.logger.Printf("proxying %q %s", req.Method, req.Host)

	if req.Method == "CONNECT" {
		p.handleConnect(w, req)
		return
	}

	client := &http.Client{
		Timeout: 1 * time.Minute,
	}

	upstreamRequest := req.Clone(context.Background())

	upstreamRequest.RequestURI = ""
	upstreamRequest.URL.Scheme = "https"

	p.logger.Printf("upstreamReq: %#v", upstreamRequest)

	removeHopByHopHeaders(upstreamRequest.Header)

	resp, err := client.Do(upstreamRequest)
	if err != nil {
		p.logger.Printf("failed to request upstream: %s", err.Error())
		http.Error(w, "failed to request upstream server", http.StatusInternalServerError)
		return
	}

	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)

	if err != nil {
		p.logger.Printf("failed to copy response body: %s", err.Error())
		http.Error(w, "failed to copy response from upstream", http.StatusInternalServerError)
		return
	}
}

func main() {
	logger := log.New(os.Stdout, "", 0)

	flag.Parse()

	address := fmt.Sprintf("%s:%d", *address, *port)

	listener, err := net.Listen("tcp", address)
	if err != nil {
		logger.Fatalf("failed to create TCP listener on %s: %s", address, err.Error())
	}

	logger.Printf("listening on %s", address)

	server := &http.Server{
		ErrorLog: logger,

		Handler: &proxyServer{
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
