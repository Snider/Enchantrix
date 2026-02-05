package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/Snider/Enchantrix/pkg/keystore"
	"github.com/spf13/cobra"
)

var (
	keystoreCmd = &cobra.Command{
		Use:   "keystore",
		Short: "Manage the encrypted key store",
		Long:  "Create, import, generate, list, and delete keys in a Trix-based encrypted key store.",
	}

	keystoreInitCmd = &cobra.Command{
		Use:   "init",
		Short: "Initialize a new key store",
		RunE:  runKeystoreInit,
	}

	keystoreImportCmd = &cobra.Command{
		Use:   "import",
		Short: "Import a password as a derived key",
		RunE:  runKeystoreImport,
	}

	keystoreGenerateCmd = &cobra.Command{
		Use:   "generate",
		Short: "Generate a new random key",
		RunE:  runKeystoreGenerate,
	}

	keystoreListCmd = &cobra.Command{
		Use:   "list",
		Short: "List stored keys (no key material shown)",
		RunE:  runKeystoreList,
	}

	keystoreDeleteCmd = &cobra.Command{
		Use:   "delete",
		Short: "Delete a key by ID",
		RunE:  runKeystoreDelete,
	}
)

func init() {
	keystoreInitCmd.Flags().StringP("path", "p", "", "Path for the new key store file (required)")
	keystoreInitCmd.MarkFlagRequired("path")

	keystoreImportCmd.Flags().StringP("path", "p", "", "Key store file path (required)")
	keystoreImportCmd.Flags().StringP("label", "l", "", "Label for the imported key (required)")
	keystoreImportCmd.Flags().StringP("type", "t", "chacha256", "Key type (chacha256)")
	keystoreImportCmd.MarkFlagRequired("path")
	keystoreImportCmd.MarkFlagRequired("label")

	keystoreGenerateCmd.Flags().StringP("path", "p", "", "Key store file path (required)")
	keystoreGenerateCmd.Flags().StringP("label", "l", "", "Label for the generated key (required)")
	keystoreGenerateCmd.Flags().StringP("type", "t", "", "Key type: chacha256, x25519, hmac (required)")
	keystoreGenerateCmd.MarkFlagRequired("path")
	keystoreGenerateCmd.MarkFlagRequired("label")
	keystoreGenerateCmd.MarkFlagRequired("type")

	keystoreListCmd.Flags().StringP("path", "p", "", "Key store file path (required)")
	keystoreListCmd.MarkFlagRequired("path")

	keystoreDeleteCmd.Flags().StringP("path", "p", "", "Key store file path (required)")
	keystoreDeleteCmd.Flags().StringP("id", "", "", "Key ID to delete (required)")
	keystoreDeleteCmd.MarkFlagRequired("path")
	keystoreDeleteCmd.MarkFlagRequired("id")

	keystoreCmd.AddCommand(keystoreInitCmd, keystoreImportCmd, keystoreGenerateCmd, keystoreListCmd, keystoreDeleteCmd)
	rootCmd.AddCommand(keystoreCmd)
}

// stdinReader returns a buffered reader for the command's stdin.
// A single reader must be used for all sequential reads from stdin
// to avoid buffering conflicts with multiple Scanner instances.
func stdinReader(cmd *cobra.Command) *bufio.Reader {
	return bufio.NewReader(cmd.InOrStdin())
}

// readLine reads a single line from the reader, trimming trailing newlines.
func readLine(r io.Reader) (string, error) {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	line, err := br.ReadString('\n')
	line = strings.TrimRight(line, "\r\n")
	if err != nil && line == "" {
		return "", err
	}
	return line, nil
}

// readMasterPassword reads the master password from ENCHANTRIX_MASTER env var
// or from the provided reader. Passwords are never passed via CLI flags to
// avoid leaking into shell history.
func readMasterPassword(cmd *cobra.Command, r *bufio.Reader) (string, error) {
	if env := os.Getenv("ENCHANTRIX_MASTER"); env != "" {
		return env, nil
	}

	fmt.Fprint(cmd.ErrOrStderr(), "Master password: ")
	pw, err := readLine(r)
	if err != nil {
		return "", fmt.Errorf("failed to read master password")
	}
	if pw == "" {
		return "", fmt.Errorf("master password cannot be empty")
	}
	return pw, nil
}

// readPasswordFromStdin reads a password from the provided reader for import operations.
func readPasswordFromStdin(cmd *cobra.Command, r *bufio.Reader) (string, error) {
	fmt.Fprint(cmd.ErrOrStderr(), "Password to import: ")
	pw, err := readLine(r)
	if err != nil {
		return "", fmt.Errorf("failed to read password")
	}
	if pw == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	return pw, nil
}

// openStore opens an existing keystore, reading master password from env/stdin.
func openStore(cmd *cobra.Command, r *bufio.Reader) (*keystore.Store, error) {
	path, _ := cmd.Flags().GetString("path")
	master, err := readMasterPassword(cmd, r)
	if err != nil {
		return nil, err
	}
	return keystore.Open(path, master)
}

func runKeystoreInit(cmd *cobra.Command, args []string) error {
	path, _ := cmd.Flags().GetString("path")
	r := stdinReader(cmd)
	master, err := readMasterPassword(cmd, r)
	if err != nil {
		return err
	}

	store, err := keystore.Create(path, master)
	if err != nil {
		return err
	}
	defer store.Close()

	fmt.Fprintf(cmd.OutOrStdout(), "Key store created: %s\n", path)
	return nil
}

func runKeystoreImport(cmd *cobra.Command, args []string) error {
	label, _ := cmd.Flags().GetString("label")
	r := stdinReader(cmd)

	store, err := openStore(cmd, r)
	if err != nil {
		return err
	}
	defer store.Close()

	password, err := readPasswordFromStdin(cmd, r)
	if err != nil {
		return err
	}

	keyID, err := store.Import(password, label)
	if err != nil {
		return err
	}

	if err := store.Save(); err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Imported key: %s (label: %s)\n", keyID, label)
	return nil
}

func runKeystoreGenerate(cmd *cobra.Command, args []string) error {
	label, _ := cmd.Flags().GetString("label")
	typeName, _ := cmd.Flags().GetString("type")

	kt := keystore.KeyType(typeName)
	if !kt.IsValid() {
		return fmt.Errorf("invalid key type %q (valid: chacha256, x25519, hmac)", typeName)
	}

	r := stdinReader(cmd)
	store, err := openStore(cmd, r)
	if err != nil {
		return err
	}
	defer store.Close()

	keyID, err := store.Generate(kt, label)
	if err != nil {
		return err
	}

	if err := store.Save(); err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Generated %s key: %s (label: %s)\n", typeName, keyID, label)
	return nil
}

func runKeystoreList(cmd *cobra.Command, args []string) error {
	r := stdinReader(cmd)
	store, err := openStore(cmd, r)
	if err != nil {
		return err
	}
	defer store.Close()

	entries := store.List()
	if len(entries) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No keys stored.")
		return nil
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tTYPE\tLABEL\tCREATED")
	for _, e := range entries {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", e.ID, e.Type, e.Label, e.CreatedAt.Format("2006-01-02 15:04:05"))
	}
	return w.Flush()
}

func runKeystoreDelete(cmd *cobra.Command, args []string) error {
	keyID, _ := cmd.Flags().GetString("id")
	r := stdinReader(cmd)

	store, err := openStore(cmd, r)
	if err != nil {
		return err
	}
	defer store.Close()

	if err := store.Delete(keyID); err != nil {
		return err
	}

	if err := store.Save(); err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Deleted key: %s\n", keyID)
	return nil
}
