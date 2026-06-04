//go:build fatal_test_mode

package enumeration

func init() {
	// For binary-level testing: make AccessDeniedException fatal so that
	// the restricted role (which triggers real AccessDeniedException at the
	// enumeration level) causes the pipeline to abort.
	fatalErrorCodes["AccessDeniedException"] = struct{}{}
}
