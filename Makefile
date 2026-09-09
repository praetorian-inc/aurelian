.PHONY: cli-docs

cli-docs:
	@GOWORK=off go test ./cmd -list 'TestCLISurface' | grep -qE '^TestCLISurface$$' \
	  || { echo "cli-docs: 'go test -list' did not report TestCLISurface in ./cmd. Either the -update writer was renamed, or the package failed to build -- run 'go build ./cmd' to tell which. 'go test -run' exits 0 when its pattern matches nothing, so without this check the target would report success having regenerated nothing at all."; exit 1; }
	GOWORK=off go test ./cmd -run 'TestCLISurface' -count=1 -update
