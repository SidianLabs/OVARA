# Install the ovara binary on Windows.
#
#   irm https://raw.githubusercontent.com/SidianLabs/OVARA/main/install.ps1 | iex
#
# Downloads the prebuilt binary from the newest GitHub release and checks
# its SHA-256. Env overrides: OVARA_VERSION (tag, default newest),
# OVARA_INSTALL_DIR (default %LOCALAPPDATA%\ovara\bin).
$ErrorActionPreference = 'Stop'

$repo = 'SidianLabs/OVARA'
$dest = if ($env:OVARA_INSTALL_DIR) { $env:OVARA_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'ovara\bin' }
$arch = if ([Environment]::Is64BitOperatingSystem) { 'amd64' } else { throw 'ovara needs 64-bit Windows' }

if ($env:OVARA_VERSION) {
    $tag = $env:OVARA_VERSION
} else {
    # Pre-releases (v0.x) are not "latest" on GitHub; take the newest release of any kind.
    $rel = Invoke-RestMethod "https://api.github.com/repos/$repo/releases?per_page=1"
    if (-not $rel) { throw "no releases published yet; build from source (see README)" }
    $tag = @($rel)[0].tag_name
}

$name = "ovara_$($tag.TrimStart('v'))_windows_$arch"
$base = if ($env:OVARA_RELEASE_BASE) { "$($env:OVARA_RELEASE_BASE)/$tag" } else { "https://github.com/$repo/releases/download/$tag" }
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("ovara-install-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "downloading ovara $tag for windows/$arch..."
    Invoke-WebRequest "$base/$name.zip" -OutFile "$tmp\$name.zip" -UseBasicParsing
    Invoke-WebRequest "$base/checksums.txt" -OutFile "$tmp\checksums.txt" -UseBasicParsing

    $want = (Get-Content "$tmp\checksums.txt" | Where-Object { $_ -match " \*?$([regex]::Escape("$name.zip"))$" }) -replace ' .*$', ''
    $got = (Get-FileHash "$tmp\$name.zip" -Algorithm SHA256).Hash.ToLower()
    if (-not $want -or $want -ne $got) { throw "checksum mismatch for $name.zip (want $want, got $got)" }

    Expand-Archive "$tmp\$name.zip" -DestinationPath $tmp -Force
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Item "$tmp\$name\ovara.exe" (Join-Path $dest 'ovara.exe') -Force
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

$exe = Join-Path $dest 'ovara.exe'
Write-Host ""
Write-Host "installed: $exe  ($(& $exe version))"
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $dest) {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$dest", 'User')
    Write-Host "added $dest to your user PATH (open a new terminal to use 'ovara')"
}
Write-Host @"

try it:
  ovara demo                                   # 30-second story, no setup
  ovara init mydir                             # keys, config and a default policy
  ovara run -dir mydir                         # start it; prints the approval-page link
  ovara env -dir mydir -shell powershell | iex # then start your agent in this shell
"@
