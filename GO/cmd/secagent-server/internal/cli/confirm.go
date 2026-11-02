package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// stdinLooksInteractive reports whether stdin is a terminal: a character device that is not /dev/null
// (a script run with `< /dev/null`, or by a supervisor with no stdin, is a character device too and must
// not be taken for an operator who can answer).
func stdinLooksInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	if null, nerr := os.Stat(os.DevNull); nerr == nil && os.SameFile(fi, null) {
		return false
	}
	return true
}

// adminStdinTTY is stdinLooksInteractive; tests replace it.
var adminStdinTTY = stdinLooksInteractive

// confirmDestructive asks for the explicit confirmation of an operation that destroys something (#233).
// yes (--yes) skips the question. Without --yes and without a terminal on stdin the operation is REFUSED
// (exit ExitRefused, nothing done): a script must say --yes on purpose. On a terminal the operator types
// the exact word (the object name), not "y".
func confirmDestructive(cmd *cobra.Command, yes bool, what, word string) error {
	if yes {
		return nil
	}
	if !adminStdinTTY() {
		return &ExitError{Code: ExitRefused, Msg: fmt.Sprintf("%s refused, nothing done: confirmation required (pass --yes in non-interactive use)", what)}
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Type %q to confirm: ", word)
	var answer string
	_, _ = fmt.Fscanln(readerOf(cmd), &answer)
	if strings.TrimSpace(answer) != word {
		return &ExitError{Code: ExitRefused, Msg: fmt.Sprintf("%s cancelled, nothing done", what)}
	}
	return nil
}

func readerOf(cmd *cobra.Command) io.Reader { return cmd.InOrStdin() }
