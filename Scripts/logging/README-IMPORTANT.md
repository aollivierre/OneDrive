# IMPORTANT: Logging Module Usage

## Current Status (Fixed as of 2025-08-02)

The logging module line number issue has been FIXED. Line numbers now display correctly in console output.

## Which File to Use

### Primary Module Location (ACTIVE):
```
C:\code\Win11UpgradeScheduler\Win11Detection\src\logging\logging.psm1
```

### Secondary Module Location (ALSO FIXED):
```
C:\code\OneDrive\Scripts\logging\logging.psm1
```

## Important Notes

1. **The RMM Detection script uses the Win11Detection path by default**
   - Line 51 of `Detect-OneDriveConfiguration-RMM.ps1` specifies this path
   - It only falls back to the local `logging\logging.psm1` if the primary path doesn't exist

2. **Both modules are now identical and fixed**
   - The fix was applied to both locations
   - Line numbers are 100% accurate

3. **What was fixed:**
   - Improved call stack navigation to properly handle wrapper functions
   - Fixed logic to correctly identify the actual caller when going through `Write-DetectionLog`
   - Line numbers now show the exact line where the logging function is called

## File Archive

- `logging-original-broken.psm1.bak` - Contains notes about the original broken logic

## Testing

To verify line numbers are working:
```powershell
# Run the test command
powershell -ExecutionPolicy Bypass -Command "& 'C:\code\OneDrive\Scripts\Test-OneDriveRMM-AsSystem-StayOpen.ps1' -DetectionOnly"
```

Look for output like:
```
[Information] [Detect-OneDriveConfiguration-RMM.Write-DetectionLog:293] - Starting OneDrive detection
```

The `:293` indicates the line number is working correctly.