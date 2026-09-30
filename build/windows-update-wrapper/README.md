# Windows Agent Update Wrapper

Build with GOOS=windows and GOARCH=amd64 or 386. Supply an immutable HTTPS agentURL and the raw agent binary's SHA-256 through Go linker flags `-X main.agentURL=... -X main.agentSHA256=...`.

The existing Windows updater requires an executable installer wrapper. This wrapper downloads the versioned raw agent, verifies SHA-256 before stopping the service, keeps a `.before-qdt5` backup, replaces the agent and restarts the existing service. Keep old versioned downloads available while their wrappers remain in circulation.
