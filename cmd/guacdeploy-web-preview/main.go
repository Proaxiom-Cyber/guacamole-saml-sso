// Separate, opt-in interaction prototype. It is not part of the setup command.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/webpreview"
)

func main() {
	mode := flag.String("mode", "agent", "agent or serve")
	origin := flag.String("relay", "http://127.0.0.1:18765", "loopback preview relay")
	flag.Parse()
	if !webpreview.LocalOrigin(*origin) {
		fmt.Fprintln(os.Stderr, "Only an explicit loopback HTTP relay is allowed in this prototype")
		os.Exit(1)
	}
	ctx, done := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer done()
	if *mode == "serve" {
		server := &http.Server{Addr: (*origin)[7:], Handler: webpreview.NewRelay(*origin), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
		go func() { <-ctx.Done(); _ = server.Close() }()
		fmt.Println("Local preview console:", *origin)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, "Preview server could not start")
			os.Exit(1)
		}
	} else if *mode == "agent" {
		if err := webpreview.RunAgent(ctx, *origin, os.Stdin, os.Stdout); err != nil && ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintln(os.Stderr, "Choose serve or agent")
		os.Exit(1)
	}
}
