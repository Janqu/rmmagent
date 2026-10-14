# QDT RMM Agent

Agent for QDT RMM, based on [Tactical RMM Agent](https://github.com/amidaware/rmmagent).
The upstream license and copyright notices remain applicable; see [LICENSE.md](LICENSE.md).

## Build

```sh
env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o qdt-rmm-agent-windows-amd64.exe
env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o qdt-rmm-agent-linux-amd64
env CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w" -o qdt-rmm-agent-darwin-arm64
```

## Headless remote desktop

Windows installers include the signed package from
`build/qdt-virtual-display/package/`. If no physical monitor is available, the
agent creates and enables `Root\QDTVirtualDisplay` for the remote session and
disables it again afterwards.

On headless Linux hosts the agent uses a private, TCP-disabled Xvfb display and
opens an xterm that can be viewed and controlled through the normal remote
desktop. Install `Xvfb`, `xauth`, `xterm`, ImageMagick (`import`), `xdotool` and
`xclip`; the agent reports the exact missing commands instead of modifying the
host package set itself.

Windows product metadata is defined in `versioninfo.json`. Regenerate the Windows resource
file for the target architecture with the existing release tooling before building a
release; a plain Go cross-build alone does not embed those resources or sign the binary.
`build/setup.iss` supplies the QDT RMM installer name and publisher.

## Branding

The agent symbol lives at `assets/qdt-rmm-agent.svg`. Use it as the source asset for
release icons, installer artwork, and RMM UI agent badges.

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
