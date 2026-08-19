// Command athena-node is the Athena host agent.
//
// It exposes a fixed set of read-only observation capabilities and executes only
// instructions signed by the Athena core it enrolled with.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/MinatoNami/project-athena/node/internal/agent"
)

const usage = `athena-node — Athena host agent

  athena-node enrol --core https://athena.example --token <enrolment-token>
  athena-node run
  athena-node version

Flags:
  --core    Athena core URL (enrol only)
  --token   single-use enrolment token (enrol only)
  --state   state directory (default /var/lib/athena-node, or $ATHENA_NODE_STATE)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	stateDir := os.Getenv("ATHENA_NODE_STATE")
	if stateDir == "" {
		stateDir = "/var/lib/athena-node"
	}

	switch os.Args[1] {
	case "enrol", "enroll":
		fs := flag.NewFlagSet("enrol", flag.ExitOnError)
		core := fs.String("core", "", "Athena core URL")
		token := fs.String("token", "", "single-use enrolment token")
		dir := fs.String("state", stateDir, "state directory")
		_ = fs.Parse(os.Args[2:])

		if *core == "" || *token == "" {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		if _, err := agent.Enrol(*core, *token, *dir); err != nil {
			slog.Error("enrolment failed", "error", err)
			os.Exit(1)
		}
		fmt.Println("Enrolled. Start the agent with: athena-node run")

	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		dir := fs.String("state", stateDir, "state directory")
		_ = fs.Parse(os.Args[2:])

		state, err := agent.Load(*dir)
		if err != nil {
			slog.Error("not enrolled", "state_dir", *dir, "error", err)
			os.Exit(1)
		}

		stop := make(chan struct{})
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-signals
			close(stop)
		}()

		if err := agent.Run(state, stop); err != nil {
			slog.Error("agent failed", "error", err)
			os.Exit(1)
		}

	case "version":
		fmt.Println(agent.Version)

	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}
