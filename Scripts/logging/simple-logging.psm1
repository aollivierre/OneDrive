#Requires -Version 5.1

<#
.SYNOPSIS
    Simplified logging module with line number support
.DESCRIPTION
    A simpler, more reliable logging module that properly captures line numbers
#>

# Module-level variables
$script:LogConfig = @{
    EnableDebug = $false
    LogPath = $null
}

function Initialize-SimpleLogging {
    param(
        [string]$LogPath,
        [switch]$EnableDebug
    )
    
    $script:LogConfig.LogPath = $LogPath
    $script:LogConfig.EnableDebug = $EnableDebug
    
    # Create log directory if needed
    if ($LogPath) {
        $logDir = Split-Path -Parent $LogPath
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
    }
}

function Write-SimpleLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Information', 'Warning', 'Error', 'Debug')]
        [string]$Level = 'Information',
        
        [Parameter()]
        [string]$FunctionName = $null
    )
    
    # Get caller information from call stack
    $callStack = Get-PSCallStack
    $caller = $null
    $lineNumber = 0
    
    # Skip through any logging wrapper functions to find the real caller
    for ($i = 1; $i -lt $callStack.Count; $i++) {
        $frame = $callStack[$i]
        if ($frame.Command -and $frame.Command -notmatch '^(Write-SimpleLog|Write-.*Log)$') {
            $caller = $frame
            $lineNumber = $frame.ScriptLineNumber
            if (-not $FunctionName) {
                $FunctionName = if ($frame.Command -like "*.ps1") { "MainScript" } else { $frame.Command }
            }
            break
        }
    }
    
    # If no function name found, use default
    if (-not $FunctionName) {
        $FunctionName = "Unknown"
    }
    
    # Get script name
    $scriptName = if ($MyInvocation.ScriptName) {
        Split-Path -Leaf $MyInvocation.ScriptName
    } else {
        "Console"
    }
    
    # Format message
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $formattedMessage = if ($lineNumber -gt 0) {
        "[$Level] [$scriptName.$FunctionName`:$lineNumber] - $Message"
    } else {
        "[$Level] [$scriptName.$FunctionName] - $Message"
    }
    
    # Console output
    if ($script:LogConfig.EnableDebug -or $Level -in @('Error', 'Warning')) {
        $color = switch ($Level) {
            'Error' { 'Red' }
            'Warning' { 'Yellow' }
            'Debug' { 'Gray' }
            default { 'White' }
        }
        Write-Host $formattedMessage -ForegroundColor $color
    }
    
    # File output
    if ($script:LogConfig.LogPath) {
        $fileMessage = "[$timestamp] $formattedMessage"
        Add-Content -Path $script:LogConfig.LogPath -Value $fileMessage -Encoding UTF8
    }
}

# Export functions
Export-ModuleMember -Function Initialize-SimpleLogging, Write-SimpleLog