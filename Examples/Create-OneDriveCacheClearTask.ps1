function Create-OneDriveCacheClearTask {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TaskPath,
        [Parameter(Mandatory = $true)]
        [string]$TaskName,
        [Parameter(Mandatory = $true)]
        [string]$ScriptDirectory,
        [Parameter(Mandatory = $true)]
        [string]$ScriptName,
        [Parameter(Mandatory = $true)]
        [string]$TaskArguments,
        [Parameter(Mandatory = $true)]
        [string]$TaskRepetitionDuration,
        [Parameter(Mandatory = $true)]
        [string]$TaskRepetitionInterval,
        [Parameter(Mandatory = $true)]
        [string]$TaskPrincipalGroupId,
        [Parameter(Mandatory = $true)]
        [string]$PowerShellPath,
        [Parameter(Mandatory = $true)]
        [string]$TaskDescription,
        [Parameter(Mandatory = $true)]
        [switch]$AtLogOn
    )

    Begin {
        Write-EnhancedLog -Message "Starting Create-OneDriveCacheClearTask function" -Level "Notice"
        Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters
    }

    Process {
        try {
            # Unregister the task if it exists
            Unregister-ScheduledTaskWithLogging -TaskName $TaskName

            $arguments = $TaskArguments.Replace("{ScriptPath}", "$ScriptDirectory\$ScriptName")

            $actionParams = @{
                Execute  = $PowerShellPath
                Argument = $arguments
            }
            $action = New-ScheduledTaskAction @actionParams

            $triggerParams = @{
                AtLogOn = $AtLogOn
            }
            
            $trigger = New-ScheduledTaskTrigger @triggerParams

            $principalParams = @{
                GroupId = $TaskPrincipalGroupId
            }
            $principal = New-ScheduledTaskPrincipal @principalParams

            $registerTaskParams = @{
                Principal   = $principal
                Action      = $action
                Trigger     = $trigger
                TaskName    = $TaskName
                Description = $TaskDescription
                TaskPath    = $TaskPath
            }
            $Task = Register-ScheduledTask @registerTaskParams

            $Task.Triggers.Repetition.Duration = $TaskRepetitionDuration
            $Task.Triggers.Repetition.Interval = $TaskRepetitionInterval
            $Task | Set-ScheduledTask
        }
        catch {
            Write-EnhancedLog -Message "An error occurred while creating the OneDrive cache clear task: $($_.Exception.Message)" -Level "ERROR"
            Handle-Error -ErrorRecord $_
        }
    }

    End {
        Write-EnhancedLog -Message "Exiting Create-OneDriveCacheClearTask function" -Level "Notice"
    }
}

# # Example usage with splatting
# $CreateOneDriveCacheClearTaskParams = @{
#     TaskPath               = "OneDriveTasks"
#     TaskName               = "Clear OneDrive Cache"
#     ScriptDirectory        = "C:\Scripts"
#     ScriptName             = "Clear-OneDriveCache.ps1"
#     TaskArguments          = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -file `"{ScriptPath}`""
#     TaskRepetitionDuration = "P1D"
#     TaskRepetitionInterval = "PT30M"
#     TaskPrincipalGroupId   = "BUILTIN\Users"
#     PowerShellPath         = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
#     TaskDescription        = "Clears the OneDrive cache by restarting the OneDrive process"
#     AtLogOn                = $true
# }

# Create-OneDriveCacheClearTask @CreateOneDriveCacheClearTaskParams