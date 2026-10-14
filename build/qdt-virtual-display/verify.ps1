$ErrorActionPreference = 'Stop'

$driver = Get-Content "$PSScriptRoot\Driver.cpp" -Raw
$inf = Get-Content "$PSScriptRoot\QdtVirtualDisplay.inf" -Raw

if ($driver -notmatch 'QDT_MONITOR_COUNT = 1') { throw 'exactly one virtual monitor is required' }
if ($driver -notmatch '1920,\s*1080,\s*60' -or $driver -notmatch '1280,\s*720,\s*60') { throw 'required modes are missing' }
if ($inf -notmatch 'Root\\QDTVirtualDisplay') { throw 'hardware ID mismatch' }
if ($inf -match '<Your|TODO: edit') { throw 'sample INF placeholders remain' }

Write-Host 'QDT Virtual Display invariants OK'
