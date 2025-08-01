# # function Create-OneDriveSyncUtilStatusTask {
# #     [CmdletBinding()]
# #     param (
# #         [Parameter(Mandatory = $true)]
# #         [string]$TaskPath,
# #         [Parameter(Mandatory = $true)]
# #         [string]$TaskName,
# #         [Parameter(Mandatory = $true)]
# #         [string]$ScriptDirectory,
# #         [Parameter(Mandatory = $true)]
# #         [string]$ScriptName,
# #         [Parameter(Mandatory = $true)]
# #         [string]$TaskArguments,
# #         [Parameter(Mandatory = $true)]
# #         [string]$TaskRepetitionDuration,
# #         [Parameter(Mandatory = $true)]
# #         [string]$TaskRepetitionInterval,
# #         [Parameter(Mandatory = $false)]
# #         [string]$TaskPrincipalGroupId,  # This will be optional now
# #         [Parameter(Mandatory = $true)]
# #         [string]$PowerShellPath,
# #         [Parameter(Mandatory = $true)]
# #         [string]$TaskDescription,
# #         [Parameter(Mandatory = $true)]
# #         [switch]$AtLogOn,
# #         [Parameter(Mandatory = $false)]
# #         [switch]$UseCurrentUser  # Add a switch to use the current logged-in user
# #     )

# #     Begin {
# #         Write-EnhancedLog -Message "Starting Create-OneDriveSyncUtilStatusTask function" -Level "Notice"
# #         Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters
# #     }

# #     Process {
# #         try {
# #             # Unregister the task if it exists
# #             Unregister-ScheduledTaskWithLogging -TaskName $TaskName

# #             $arguments = $TaskArguments.Replace("{ScriptPath}", "$ScriptDirectory\$ScriptName")

# #             $actionParams = @{
# #                 Execute  = $PowerShellPath
# #                 Argument = $arguments
# #             }
# #             $action = New-ScheduledTaskAction @actionParams

# #             $triggerParams = @{
# #                 AtLogOn = $AtLogOn
# #             }
            
# #             $trigger = New-ScheduledTaskTrigger @triggerParams

# #             # Determine whether to use GroupId or Current Logged-in User
# #             if ($UseCurrentUser) {
# #                 $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
# #                 $principalParams = @{
# #                     UserId = $currentUser
# #                 }
# #                 Write-EnhancedLog -Message "Using current logged-in user: $currentUser" -Level "INFO"
# #             }
# #             else {
# #                 $principalParams = @{
# #                     GroupId = $TaskPrincipalGroupId
# #                 }
# #                 Write-EnhancedLog -Message "Using group ID: $TaskPrincipalGroupId" -Level "INFO"
# #             }

# #             $principal = New-ScheduledTaskPrincipal @principalParams

# #             $registerTaskParams = @{
# #                 Principal   = $principal
# #                 Action      = $action
# #                 Trigger     = $trigger
# #                 TaskName    = $TaskName
# #                 Description = $TaskDescription
# #                 TaskPath    = $TaskPath
# #             }
# #             $Task = Register-ScheduledTask @registerTaskParams

# #             $Task.Triggers.Repetition.Duration = $TaskRepetitionDuration
# #             $Task.Triggers.Repetition.Interval = $TaskRepetitionInterval
# #             $Task | Set-ScheduledTask
# #         }
# #         catch {
# #             Write-EnhancedLog -Message "An error occurred while creating the OneDrive sync status task: $($_.Exception.Message)" -Level "ERROR"
# #             Handle-Error -ErrorRecord $_
# #         }
# #     }

# #     End {
# #         Write-EnhancedLog -Message "Exiting Create-OneDriveSyncUtilStatusTask function" -Level "Notice"
# #     }
# # }




# # function Create-OneDriveSyncUtilStatusTask {
# #     [CmdletBinding()]
# #     param (
# #         [Parameter(Mandatory = $true)]
# #         [string]$TaskPath,
# #         [Parameter(Mandatory = $true)]
# #         [string]$TaskName,
# #         [Parameter(Mandatory = $true)]
# #         [string]$ScriptDirectory,
# #         [Parameter(Mandatory = $true)]
# #         [string]$ScriptName,
# #         [Parameter(Mandatory = $true)]
# #         [string]$TaskArguments,
# #         [Parameter(Mandatory = $true)]
# #         [string]$TaskRepetitionDuration,
# #         [Parameter(Mandatory = $true)]
# #         [string]$TaskRepetitionInterval,
# #         [Parameter(Mandatory = $false)]
# #         [string]$TaskPrincipalGroupId,  # This will be optional now
# #         [Parameter(Mandatory = $true)]
# #         [string]$PowerShellPath,
# #         [Parameter(Mandatory = $true)]
# #         [string]$TaskDescription,
# #         [Parameter(Mandatory = $true)]
# #         [switch]$AtLogOn,
# #         [Parameter(Mandatory = $false)]
# #         [switch]$UseCurrentUser,  # Add a switch to use the current logged-in user
# #         [Parameter(Mandatory = $false)]
# #         [switch]$HideWithVBS,     # Optional switch to hide execution with VBS
# #         [Parameter(Mandatory = $false)]
# #         [string]$VbsFileName = "run-ps-hidden.vbs" # Optional parameter for VBS file name
# #     )

# #     Begin {
# #         Write-EnhancedLog -Message "Starting Create-OneDriveSyncUtilStatusTask function" -Level "Notice"
# #         Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters
# #     }

# #     Process {
# #         try {
# #             # Unregister the task if it exists
# #             Unregister-ScheduledTaskWithLogging -TaskName $TaskName

# #             # Prepare the script path and arguments
# #             $scriptFullPath = Join-Path -Path $ScriptDirectory -ChildPath $ScriptName
# #             $arguments = $TaskArguments.Replace("{ScriptPath}", $scriptFullPath)

# #             # If hiding the execution, create the VBS script and modify the task action
# #             if ($HideWithVBS) {
# #                 Write-EnhancedLog -Message "Creating VBScript for hidden execution" -Level "INFO"
# #                 $vbsScriptPath = Create-VBShiddenPS -Path_local $ScriptDirectory -FileName $VbsFileName
# #                 $arguments = "`"$vbsScriptPath`""
# #                 $actionParams = @{
# #                     Execute  = "wscript.exe"
# #                     Argument = $arguments
# #                 }
# #             } else {
# #                 # Regular execution using PowerShell
# #                 $actionParams = @{
# #                     Execute  = $PowerShellPath
# #                     Argument = $arguments
# #                 }
# #             }

# #             $action = New-ScheduledTaskAction @actionParams

# #             # Set up the trigger
# #             $triggerParams = @{
# #                 AtLogOn = $AtLogOn
# #             }
# #             $trigger = New-ScheduledTaskTrigger @triggerParams

# #             # Determine whether to use GroupId or Current Logged-in User
# #             if ($UseCurrentUser) {
# #                 $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
# #                 $principalParams = @{
# #                     UserId = $currentUser
# #                 }
# #                 Write-EnhancedLog -Message "Using current logged-in user: $currentUser" -Level "INFO"
# #             } else {
# #                 $principalParams = @{
# #                     GroupId = $TaskPrincipalGroupId
# #                 }
# #                 Write-EnhancedLog -Message "Using group ID: $TaskPrincipalGroupId" -Level "INFO"
# #             }

# #             $principal = New-ScheduledTaskPrincipal @principalParams

# #             # Register the task
# #             $registerTaskParams = @{
# #                 Principal   = $principal
# #                 Action      = $action
# #                 Trigger     = $trigger
# #                 TaskName    = $TaskName
# #                 Description = $TaskDescription
# #                 TaskPath    = $TaskPath
# #             }
# #             $Task = Register-ScheduledTask @registerTaskParams

# #             # Set task repetition parameters
# #             $Task.Triggers.Repetition.Duration = $TaskRepetitionDuration
# #             $Task.Triggers.Repetition.Interval = $TaskRepetitionInterval
# #             $Task | Set-ScheduledTask
# #         }
# #         catch {
# #             Write-EnhancedLog -Message "An error occurred while creating the OneDrive sync status task: $($_.Exception.Message)" -Level "ERROR"
# #             Handle-Error -ErrorRecord $_
# #         }
# #     }

# #     End {
# #         Write-EnhancedLog -Message "Exiting Create-OneDriveSyncUtilStatusTask function" -Level "Notice"
# #     }
# # }




# # function Create-OneDriveSyncUtilStatusTask {
# #     [CmdletBinding()]
# #     param (
# #         [Parameter(Mandatory = $true)]
# #         [string]$TaskPath,
# #         [Parameter(Mandatory = $true)]
# #         [string]$TaskName,
# #         [Parameter(Mandatory = $true)]
# #         [string]$ScriptDirectory,
# #         [Parameter(Mandatory = $true)]
# #         [string]$ScriptName,
# #         [Parameter(Mandatory = $true)]
# #         [string]$TaskArguments,
# #         [Parameter(Mandatory = $true)]
# #         [string]$TaskRepetitionDuration,
# #         [Parameter(Mandatory = $true)]
# #         [string]$TaskRepetitionInterval,
# #         [Parameter(Mandatory = $false)]
# #         [string]$TaskPrincipalGroupId,  # This will be optional now
# #         [Parameter(Mandatory = $true)]
# #         [string]$PowerShellPath,
# #         [Parameter(Mandatory = $true)]
# #         [string]$TaskDescription,
# #         [Parameter(Mandatory = $true)]
# #         [switch]$AtLogOn,
# #         [Parameter(Mandatory = $false)]
# #         [switch]$UseCurrentUser,  # Add a switch to use the current logged-in user
# #         [Parameter(Mandatory = $false)]
# #         [switch]$HideWithVBS,     # Optional switch to hide execution with VBS
# #         [Parameter(Mandatory = $false)]
# #         [string]$VbsFileName = "run-ps-hidden.vbs" # Optional parameter for VBS file name
# #     )

# #     Begin {
# #         Write-EnhancedLog -Message "Starting Create-OneDriveSyncUtilStatusTask function" -Level "Notice"
# #         Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters
# #     }

# #     Process {
# #         try {
# #             # Unregister the task if it exists
# #             Unregister-ScheduledTaskWithLogging -TaskName $TaskName

# #             # Prepare the script path and arguments
# #             $scriptFullPath = Join-Path -Path $ScriptDirectory -ChildPath $ScriptName

# #             # Check if HideWithVBS is set, create VBScript for hidden execution
# #             if ($HideWithVBS) {
# #                 Write-EnhancedLog -Message "Creating VBScript for hidden execution" -Level "INFO"
# #                 $vbsScriptPath = Create-VBShiddenPS -Path_local $ScriptDirectory -FileName $VbsFileName

# #                 # Set the task action to use wscript.exe with the VBScript and PowerShell script as arguments
# #                 $arguments = "`"$vbsScriptPath`" `"$scriptFullPath`""
# #                 $actionParams = @{
# #                     Execute  = "C:\Windows\System32\wscript.exe"
# #                     Argument = $arguments
# #                 }
# #             } else {
# #                 # Regular execution using PowerShell
# #                 $arguments = $TaskArguments.Replace("{ScriptPath}", $scriptFullPath)
# #                 $actionParams = @{
# #                     Execute  = $PowerShellPath
# #                     Argument = $arguments
# #                 }
# #             }

# #             $action = New-ScheduledTaskAction @actionParams

# #             # Set up the trigger
# #             $triggerParams = @{
# #                 AtLogOn = $AtLogOn
# #             }
# #             $trigger = New-ScheduledTaskTrigger @triggerParams

# #             # Determine whether to use GroupId or Current Logged-in User
# #             if ($UseCurrentUser) {
# #                 $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
# #                 $principalParams = @{
# #                     UserId = $currentUser
# #                 }
# #                 Write-EnhancedLog -Message "Using current logged-in user: $currentUser" -Level "INFO"
# #             } else {
# #                 $principalParams = @{
# #                     GroupId = $TaskPrincipalGroupId
# #                 }
# #                 Write-EnhancedLog -Message "Using group ID: $TaskPrincipalGroupId" -Level "INFO"
# #             }

# #             $principal = New-ScheduledTaskPrincipal @principalParams

# #             # Register the task
# #             $registerTaskParams = @{
# #                 Principal   = $principal
# #                 Action      = $action
# #                 Trigger     = $trigger
# #                 TaskName    = $TaskName
# #                 Description = $TaskDescription
# #                 TaskPath    = $TaskPath
# #             }
# #             $Task = Register-ScheduledTask @registerTaskParams

# #             # Set task repetition parameters
# #             $Task.Triggers.Repetition.Duration = $TaskRepetitionDuration
# #             $Task.Triggers.Repetition.Interval = $TaskRepetitionInterval
# #             $Task | Set-ScheduledTask
# #         }
# #         catch {
# #             Write-EnhancedLog -Message "An error occurred while creating the OneDrive sync status task: $($_.Exception.Message)" -Level "ERROR"
# #             Handle-Error -ErrorRecord $_
# #         }
# #     }

# #     End {
# #         Write-EnhancedLog -Message "Exiting Create-OneDriveSyncUtilStatusTask function" -Level "Notice"
# #     }
# # }





# function Create-OneDriveSyncUtilStatusTask {
#     [CmdletBinding()]
#     param (
#         [Parameter(Mandatory = $true)]
#         [string]$TaskPath,
#         [Parameter(Mandatory = $true)]
#         [string]$TaskName,
#         [Parameter(Mandatory = $true)]
#         [string]$ScriptDirectory,
#         [Parameter(Mandatory = $true)]
#         [string]$ScriptName,
#         [Parameter(Mandatory = $true)]
#         [string]$TaskArguments,
#         [Parameter(Mandatory = $false)]
#         [string]$TaskRepetitionDuration = "P1D",  # Default duration of 1 day
#         [Parameter(Mandatory = $false)]
#         [string]$TaskRepetitionInterval = "PT30M", # Default interval of 30 minutes
#         [Parameter(Mandatory = $false)]
#         [switch]$EnableRepetition,  # New switch to enable repetition
#         [Parameter(Mandatory = $false)]
#         [string]$TaskPrincipalGroupId,  # This will be optional now
#         [Parameter(Mandatory = $true)]
#         [string]$PowerShellPath,
#         [Parameter(Mandatory = $true)]
#         [string]$TaskDescription,
#         [Parameter(Mandatory = $true)]
#         [switch]$AtLogOn,
#         [Parameter(Mandatory = $false)]
#         [switch]$UseCurrentUser,  # Add a switch to use the current logged-in user
#         [Parameter(Mandatory = $false)]
#         [switch]$HideWithVBS,     # Optional switch to hide execution with VBS
#         [Parameter(Mandatory = $false)]
#         [string]$VbsFileName = "run-ps-hidden.vbs" # Optional parameter for VBS file name
#     )

#     Begin {
#         Write-EnhancedLog -Message "Starting Create-OneDriveSyncUtilStatusTask function" -Level "Notice"
#         Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters
#     }

#     Process {
#         try {
#             # Unregister the task if it exists
#             Unregister-ScheduledTaskWithLogging -TaskName $TaskName

#             # Prepare the script path and arguments
#             $scriptFullPath = Join-Path -Path $ScriptDirectory -ChildPath $ScriptName

#             # Check if HideWithVBS is set, create VBScript for hidden execution
#             if ($HideWithVBS) {
#                 Write-EnhancedLog -Message "Creating VBScript for hidden execution" -Level "INFO"
#                 $vbsScriptPath = Create-VBShiddenPS -Path_local $ScriptDirectory -FileName $VbsFileName

#                 # Set the task action to use wscript.exe with the VBScript and PowerShell script as arguments
#                 $arguments = "`"$vbsScriptPath`" `"$scriptFullPath`""
#                 $actionParams = @{
#                     Execute  = "C:\Windows\System32\wscript.exe"
#                     Argument = $arguments
#                 }
#             } else {
#                 # Regular execution using PowerShell
#                 $arguments = $TaskArguments.Replace("{ScriptPath}", $scriptFullPath)
#                 $actionParams = @{
#                     Execute  = $PowerShellPath
#                     Argument = $arguments
#                 }
#             }

#             $action = New-ScheduledTaskAction @actionParams

#             # Set up the trigger
#             $triggerParams = @{
#                 AtLogOn = $AtLogOn
#             }
#             $trigger = New-ScheduledTaskTrigger @triggerParams

#             # Determine whether to use GroupId or Current Logged-in User
#             if ($UseCurrentUser) {
#                 $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
#                 $principalParams = @{
#                     UserId = $currentUser
#                 }
#                 Write-EnhancedLog -Message "Using current logged-in user: $currentUser" -Level "INFO"
#             } else {
#                 $principalParams = @{
#                     GroupId = $TaskPrincipalGroupId
#                 }
#                 Write-EnhancedLog -Message "Using group ID: $TaskPrincipalGroupId" -Level "INFO"
#             }

#             $principal = New-ScheduledTaskPrincipal @principalParams

#             # Register the task with the repetition settings if enabled
#             $registerTaskParams = @{
#                 Principal   = $principal
#                 Action      = $action
#                 Trigger     = $trigger
#                 TaskName    = $TaskName
#                 Description = $TaskDescription
#                 TaskPath    = $TaskPath
#             }

#             # Register the task
#             $Task = Register-ScheduledTask @registerTaskParams

#             # Set task repetition parameters only if the EnableRepetition switch is used
#             if ($EnableRepetition) {
#                 Write-EnhancedLog -Message "Setting task repetition with duration $TaskRepetitionDuration and interval $TaskRepetitionInterval" -Level "INFO"
#                 $Task.Triggers.Repetition.Duration = $TaskRepetitionDuration
#                 $Task.Triggers.Repetition.Interval = $TaskRepetitionInterval
#                 $Task | Set-ScheduledTask
#             } else {
#                 Write-EnhancedLog -Message "Task repetition not enabled." -Level "INFO"
#             }
#         }
#         catch {
#             Write-EnhancedLog -Message "An error occurred while creating the OneDrive sync status task: $($_.Exception.Message)" -Level "ERROR"
#             Handle-Error -ErrorRecord $_
#         }
#     }

#     End {
#         Write-EnhancedLog -Message "Exiting Create-OneDriveSyncUtilStatusTask function" -Level "Notice"
#     }
# }







# # $CreateOneDriveSyncUtilStatusTask = @{
# #     TaskPath               = "AAD Migration"
# #     TaskName               = "AADM Get OneDrive Sync Status"
# #     ScriptDirectory        = "C:\ProgramData\AADMigration\Scripts"
# #     ScriptName             = "Check-OneDriveSyncStatus.ps1"
# #     TaskArguments          = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -file `"{ScriptPath}`""
# #     TaskRepetitionDuration = "P1D"
# #     TaskRepetitionInterval = "PT30M"
# #     PowerShellPath         = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
# #     TaskDescription        = "Get current OneDrive Sync Status and write to event log"
# #     AtLogOn                = $true
# #     UseCurrentUser         = $true  # Specify to use the current user
# # }

# # Create-OneDriveSyncUtilStatusTask @CreateOneDriveSyncUtilStatusTask
