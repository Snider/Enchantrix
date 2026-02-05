package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Snider/Enchantrix/pkg/keyserver"
	"github.com/Snider/Enchantrix/pkg/keystore"
	"github.com/spf13/cobra"
)

var (
	keyserverCmd = &cobra.Command{
		Use:   "keyserver",
		Short: "Manage and run the keyserver",
		Long:  "Start the keyserver process and manage sessions for capability-based access to crypto operations.",
	}

	keyserverStartCmd = &cobra.Command{
		Use:   "start",
		Short: "Start the keyserver (blocks until interrupted)",
		Long:  "Opens the key store and keeps the keyserver running. Reads master password from stdin or ENCHANTRIX_MASTER env.",
		RunE:  runKeyserverStart,
	}

	keyserverSessionCmd = &cobra.Command{
		Use:   "session",
		Short: "Manage keyserver sessions",
	}

	keyserverSessionCreateCmd = &cobra.Command{
		Use:   "create",
		Short: "Create a new session token",
		RunE:  runKeyserverSessionCreate,
	}
)

func init() {
	keyserverStartCmd.Flags().StringP("store", "s", "", "Key store file path (required)")
	keyserverStartCmd.Flags().StringP("addr", "a", ":9100", "Listen address (for future network use)")
	keyserverStartCmd.MarkFlagRequired("store")

	keyserverSessionCreateCmd.Flags().StringP("store", "s", "", "Key store file path (required)")
	keyserverSessionCreateCmd.Flags().StringP("caps", "c", "", "Capabilities: comma-separated op:keyID pairs (required)")
	keyserverSessionCreateCmd.Flags().StringP("ttl", "", "1h", "Session time-to-live (e.g. 1h, 30m, 24h)")
	keyserverSessionCreateCmd.Flags().StringP("client", "", "", "Client identifier")
	keyserverSessionCreateCmd.MarkFlagRequired("store")
	keyserverSessionCreateCmd.MarkFlagRequired("caps")

	keyserverSessionCmd.AddCommand(keyserverSessionCreateCmd)
	keyserverCmd.AddCommand(keyserverStartCmd, keyserverSessionCmd)
	rootCmd.AddCommand(keyserverCmd)
}

func runKeyserverStart(cmd *cobra.Command, args []string) error {
	storePath, _ := cmd.Flags().GetString("store")
	addr, _ := cmd.Flags().GetString("addr")

	r := stdinReader(cmd)
	master, err := readMasterPassword(cmd, r)
	if err != nil {
		return err
	}

	store, err := keystore.Open(storePath, master)
	if err != nil {
		return err
	}

	ks := keyserver.NewServer(store)
	_ = ks // server is ready for in-process callers

	fmt.Fprintf(cmd.OutOrStdout(), "Keyserver started (store: %s, addr: %s)\n", storePath, addr)
	fmt.Fprintf(cmd.OutOrStdout(), "Keys loaded: %d\n", len(store.List()))
	fmt.Fprintln(cmd.OutOrStdout(), "Press Ctrl+C to stop.")

	// Block until signal
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		fmt.Fprintf(cmd.OutOrStdout(), "\nReceived %s, shutting down...\n", sig)
	case <-ctx.Done():
	}

	store.Close()
	fmt.Fprintln(cmd.OutOrStdout(), "Keyserver stopped. Key material zeroed.")
	return nil
}

func runKeyserverSessionCreate(cmd *cobra.Command, args []string) error {
	storePath, _ := cmd.Flags().GetString("store")
	capsStr, _ := cmd.Flags().GetString("caps")
	ttlStr, _ := cmd.Flags().GetString("ttl")
	clientID, _ := cmd.Flags().GetString("client")

	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		return fmt.Errorf("invalid TTL %q: %w", ttlStr, err)
	}

	caps, err := keyserver.ParseCapabilities(capsStr)
	if err != nil {
		return err
	}

	r := stdinReader(cmd)
	master, err := readMasterPassword(cmd, r)
	if err != nil {
		return err
	}

	store, err := keystore.Open(storePath, master)
	if err != nil {
		return err
	}
	defer store.Close()

	sm := keyserver.NewSessionManager()
	ctx := context.Background()

	session, err := sm.CreateSession(ctx, clientID, caps, ttl)
	if err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Session ID:    %s\n", session.ID)
	fmt.Fprintf(cmd.OutOrStdout(), "Client:        %s\n", session.ClientID)
	fmt.Fprintf(cmd.OutOrStdout(), "Expires:       %s\n", session.ExpiresAt.Format(time.RFC3339))
	fmt.Fprintln(cmd.OutOrStdout(), "Capabilities:")
	for _, c := range session.Capabilities {
		fmt.Fprintf(cmd.OutOrStdout(), "  - %s\n", c)
	}

	return nil
}
