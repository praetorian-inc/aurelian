// internal/message/message.go
package message

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/fatih/color"
	"github.com/praetorian-inc/aurelian/version"
)

var (
	quiet     bool = true
	noColor   bool
	silent    bool
	mutex     sync.RWMutex
	outWriter io.Writer = os.Stderr

	// Color definitions
	infoColor    = color.New(color.FgCyan)
	successColor = color.New(color.FgGreen)
	warningColor = color.New(color.FgYellow)
	errorColor   = color.New(color.FgRed)
	bannerColor  = color.RGB(230, 57, 72)
	sectionColor = color.RGB(17, 195, 219)
)

var asciiBanner = "\n" +
	"                      _ _             \n" +
	"  __ _ _   _ _ __ ___| (_) __ _ _ __  \n" +
	" / _` | | | | '__/ _ \\ | |/ _` | '_ \\ \n" +
	"| (_| | |_| | | |  __/ | | (_| | | | |\n" +
	" \\__,_|\\__,_|_|  \\___|_|_|\\__,_|_| |_|\n"

// SetQuiet enables/disables user messages
func SetQuiet(q bool) {
	mutex.Lock()
	defer mutex.Unlock()
	quiet = q
}

// SetNoColor enables/disables colored output
func SetNoColor(nc bool) {
	mutex.Lock()
	defer mutex.Unlock()
	noColor = nc
	color.NoColor = nc // This affects the color package globally
}

// SetSilent enables/disables all messages
func SetSilent(s bool) {
	mutex.Lock()
	defer mutex.Unlock()
	silent = s
}

// SetOutput changes the output writer (useful for testing)
func SetOutput(w io.Writer) {
	mutex.Lock()
	defer mutex.Unlock()
	outWriter = w
}

func printf(c *color.Color, prefix, format string, args ...any) {
	mutex.Lock() // Use exclusive lock instead of RLock
	defer mutex.Unlock()

	if !quiet {
		msg := fmt.Sprintf(format, args...)
		useColor := !noColor // Capture decision atomically
		if useColor {
			c.Fprintf(outWriter, "%s%s\n", prefix, msg)
		} else {
			fmt.Fprintf(outWriter, "%s%s\n", prefix, msg)
		}
	}
}

// Info prints an informational message unless quiet/silent mode is enabled
func Info(format string, args ...any) {
	if quiet || silent {
		return
	}
	printf(infoColor, "[*]", format, args...)
}

// Success prints a success message unless quiet/silent mode is enabled
func Success(format string, args ...any) {
	if quiet || silent {
		return
	}
	printf(successColor, "[+] ", format, args...)
}

// Warning prints a warning message unless silent mode is enabled
func Warning(format string, args ...any) {
	if silent {
		return
	}
	printf(warningColor, "[!] ", format, args...)
}

// Error prints an error message unless silent mode is enabled
func Error(format string, args ...any) {
	if silent {
		return
	}
	printf(errorColor, "[-] ", format, args...)
}

// Critical prints a critical error message that is never suppressed
func Critical(format string, args ...any) {
	printf(errorColor, "[!!] ", format, args...)
}

// Emphasize returns a string with bold formatting
func Emphasize(s string) string {
	mutex.RLock()
	defer mutex.RUnlock()
	if noColor {
		return s
	}
	return color.New(color.Bold).Sprint(s)
}

// Section prints a section header in bold cyan
func Section(format string, args ...any) {
	if quiet || silent {
		return
	}
	msg := fmt.Sprintf(format, args...)
	printf(sectionColor, "\n-=[", "%s]=-\n", msg)
}

// Prints the banner
func Banner(modules int) {
	if quiet || silent {
		return
	}

	mutex.RLock()
	defer mutex.RUnlock()

	if !quiet {
		if noColor {
			fmt.Fprint(outWriter, asciiBanner, version.AbbreviatedVersion(), "\n", fmt.Sprintf("%d modules", modules), "\n")
		} else {
			bannerColor.Fprint(outWriter, asciiBanner, version.AbbreviatedVersion(), "\n", fmt.Sprintf("%d modules", modules), "\n")
		}
	}
}
