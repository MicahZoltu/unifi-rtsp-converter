# tools/tls_selftest.ps1
#
# Step-17 localhost TLS self-test client (throwaway validation scaffolding).
# Connects to the `protect_recon --selftest` listener (which echoes decrypted
# bytes back through the hand-rolled `tls_schannel` SChannel module) and
# round-trips three buffer sizes:
#   * 1 B    — exercises a minimal single-record encrypt/decrypt.
#   * 64 KiB — a typical multi-record frame.
#   * 1 MiB  — stresses the encrypt/decrypt buffer state machine across many
#              records and the read-side record-spanning / multiple-records-
#              per-read paths.
#
# For each size the script writes all bytes via WriteAsync (ThreadPool) while
# reading the echo on the main thread (SslStream supports one concurrent read
# + one concurrent write per .NET docs), so TCP flow control never deadlocks
# on the 1 MiB case, then asserts the echoed bytes are byte-identical, and
# finally drives a clean SslStream shutdown so the listener's `shutdown()`
# (close_notify) path is exercised.
#
# Usage (run on the Windows target host):
#   protect_recon.exe --selftest --password recon
#   # (prints: selftest listening on 127.0.0.1:<port>)
#   powershell -ExecutionPolicy Bypass -File ./tools/tls_selftest.ps1 -Port <port>
#
# Exit code 0 = all three round-trips byte-identical + clean shutdown.

param(
    [Parameter(Mandatory = $true)]
    [int]$Port
)

$ErrorActionPreference = "Stop"

# Round-trip sizes (bytes): 1 B, 64 KiB, 1 MiB. Computed on separate lines so
# PowerShell's comma/asterisk operator precedence (comma binds tighter than
# `*`, so `1, 64 * 1024` would replicate the array, not multiply 64) cannot
# surprise us.
$size1b  = 1
$size64k = 64 * 1024
$size1m  = 1024 * 1024
$sizes = @($size1b, $size64k, $size1m)

# "Always trust the self-signed recon cert" callback, built as an explicit
# RemoteCertificateValidationCallback delegate so New-Object/::new overload
# resolution on the SslStream constructors cannot pick the wrong overload.
$trustCallback = [System.Net.Security.RemoteCertificateValidationCallback] {
    param($sender, $cert, $chain, $errors)
    return $true
}

function New-RoundTripPayload {
    param([int]$Size)
    # Deterministic but varied bytes so a truncation/swap bug is visible.
    $bytes = [byte[]]::new($Size)
    for ($i = 0; $i -lt $Size; $i++) {
        $bytes[$i] = ($i * 7 + 13) % 256
    }
    return $bytes
}

function Invoke-RoundTrip {
    param(
        [System.Net.Sockets.TcpClient]$Client,
        [int]$Size
    )
    $stream = $Client.GetStream()
    $ssl = [System.Net.Security.SslStream]::new($stream, $false, $trustCallback)
    try {
        $ssl.AuthenticateAsClient("protect-recon")
    } catch {
        throw "TLS handshake failed: $_"
    }

    $payload  = New-RoundTripPayload -Size $Size
    $received = [byte[]]::new($Size)

    # SslStream supports one concurrent read and one concurrent write (per
    # .NET docs). Start the write on the ThreadPool via WriteAsync and read
    # the echo on the main thread so the 1 MiB case doesn't deadlock (client
    # blocked on send while the server is blocked on send-back). We do NOT use
    # Start-Job here: a background job runs in a separate process and cannot
    # serialize an SslStream across the boundary.
    $writeTask = $ssl.WriteAsync($payload, 0, $payload.Length)

    $read = 0
    while ($read -lt $Size) {
        $n = $ssl.Read($received, $read, $Size - $read)
        if ($n -le 0) { break }
        $read += $n
    }
    if ($read -ne $Size) {
        $writeTask.Wait()
        throw "short read: expected $Size bytes, got $read"
    }
    $writeTask.Wait()

    # Byte-identical assertion.
    for ($i = 0; $i -lt $Size; $i++) {
        if ($received[$i] -ne $payload[$i]) {
            throw "mismatch at byte $i : sent $($payload[$i]), received $($received[$i])"
        }
    }

    # Clean shutdown: close the TLS layer so the server's close_notify path runs.
    $ssl.Close()
    Write-Host ("  {0,8} byte(s): OK" -f $Size)
}

Write-Host "tls_selftest: connecting to 127.0.0.1:$Port"
foreach ($size in $sizes) {
    $client = New-Object System.Net.Sockets.TcpClient("127.0.0.1", $Port)
    try {
        Invoke-RoundTrip -Client $client -Size $size
    } finally {
        $client.Close()
    }
}

Write-Host "tls_selftest: PASS (all round-trips byte-identical, clean shutdown)"
exit 0