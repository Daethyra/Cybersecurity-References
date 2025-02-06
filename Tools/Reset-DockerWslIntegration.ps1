<#
.SYNOPSIS
This module provides functions to reset Docker WSL integration.

.DESCRIPTION
The module includes functions to stop Docker Desktop, stop WSL, and unregister Docker WSL data.

.NOTES
Version:        1.2
Author:         Daethyra
#>

function Stop-DockerDesktop {
    <#
    .SYNOPSIS
    Stops the Docker Desktop process.

    .DESCRIPTION
    Attempts to stop the Docker Desktop process. Writes an error if the process cannot be stopped.
    #>

    try {
        $processes = Get-Process -Name "*Docker Desktop*" -ErrorAction SilentlyContinue
        if (-not $processes) {
            Write-Output "No Docker Desktop processes found."
            return
        }

        $processes | Stop-Process -Force
        Start-Sleep -Seconds 3  # Allow time for process termination
        Write-Output "Docker Desktop processes stopped successfully."
    }
    catch {
        Write-Error "Error stopping Docker Desktop processes: $_"
        throw
    }
}

function Stop-Wsl {
    <#
    .SYNOPSIS
    Shuts down the Windows Subsystem for Linux (WSL).

    .DESCRIPTION
    Tries to shut down WSL up to a specified number of attempts.
    #>

    param (
        [int]$maxAttempts = 3
    )

    for ($i = 1; $i -le $maxAttempts; $i++) {
        Write-Output "Attempting WSL shutdown (Attempt $i/$maxAttempts)"
        wsl --shutdown

        if ($LASTEXITCODE -eq 0) {
            Write-Output "WSL shut down successfully."
            Start-Sleep -Seconds 5  # Allow time for full shutdown
            return
        }

        Write-Warning "WSL shutdown attempt $i failed."
        if ($i -lt $maxAttempts) {
            Start-Sleep -Seconds 2
        }
    }

    $errorMsg = "Failed to shut down WSL after $maxAttempts attempts."
    Write-Error $errorMsg
    throw $errorMsg
}

function Unregister-DockerWsl {
    <#
    .SYNOPSIS
    Unregisters the docker-desktop-data from WSL.

    .DESCRIPTION
    Attempts to unregister the docker-desktop-data. Writes an error if the operation fails.
    #>

    try {
        Write-Output "Unregistering docker-desktop-data..."
        wsl --unregister docker-desktop-data

        if ($LASTEXITCODE -ne 0) {
            throw "wsl command failed with exit code $LASTEXITCODE"
        }

        Write-Output "docker-desktop-data unregistered successfully."
        Start-Sleep -Seconds 2  # Allow time for unregistration to complete
    }
    catch {
        Write-Error "Error unregistering docker-desktop-data: $_"
        throw
    }
}

# Main script
try {
    Write-Output "Starting Docker WSL integration reset process."

    Write-Output "Stopping Docker Desktop..."
    Stop-DockerDesktop

    Write-Output "Shutting down WSL..."
    Stop-Wsl

    Write-Output "Unregistering docker-desktop-data..."
    Unregister-DockerWsl

    Write-Output "Docker WSL integration successfully reset."
}
catch {
    Write-Error "Reset failed: $_"
    exit 1
}