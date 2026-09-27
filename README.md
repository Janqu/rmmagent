# QDT RMM Agent

Agent for QDT RMM, based on [Tactical RMM Agent](https://github.com/amidaware/rmmagent).
The upstream license and copyright notices remain applicable; see [LICENSE.md](LICENSE.md).

## Build

```sh
env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o qdt-rmm-agent-windows-amd64.exe
env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o qdt-rmm-agent-linux-amd64
env CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w" -o qdt-rmm-agent-darwin-arm64
```

Windows product metadata is defined in `versioninfo.json`. Regenerate the Windows resource
file for the target architecture with the existing release tooling before building a
release; a plain Go cross-build alone does not embed those resources or sign the binary.
`build/setup.iss` supplies the QDT RMM installer name and publisher.

## Compatibility

QDT RMM is the visible product name. Existing protocol and upgrade identifiers remain
unchanged: the Windows service `tacticalrmm`, installed executable `tacticalrmm.exe`,
`TacticalAgent` installation directory, `SOFTWARE\TacticalRMM` registry keys,
`TacticalRMM_*` scheduled tasks, and Unix `tacticalagent` service/configuration paths.
The Go module, update/installer filenames and upstream license references also remain
compatible. When packaging with the current installer, supply the compiled Windows
binary under its expected `tacticalrmm.exe` filename. Existing installed service labels
change when the service is installed again; this source change does not migrate them.

No production endpoints or agent registrations are changed by building this source.
