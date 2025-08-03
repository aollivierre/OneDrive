# Files On-Demand and Storage Sense: Complete Guide

## Overview
Two complementary features work together to optimize disk space with OneDrive:
1. **Files On-Demand** (OneDrive feature) - Makes files visible without using local space
2. **Storage Sense** (Windows feature) - Automatically converts unused files to online-only

## Files On-Demand

### What it does:
- Shows all OneDrive files in File Explorer
- Files remain "online-only" with cloud icon (don't use disk space)
- Downloads files when you open them
- Allows manual control via right-click menu:
  - "Always keep on this device" - Download and keep locally
  - "Free up space" - Convert back to online-only

### Key Points:
- **Enabled by default** since OneDrive build 23.066 (March 2024)
- Works on Windows 10 1709+ and Windows 11
- Functions independently of Storage Sense
- Users can manually manage which files use disk space

## Storage Sense

### What it does:
- Windows feature that automatically manages disk space
- Triggers Files On-Demand to convert unused files to online-only
- Default: Converts files not opened for 30 days (configurable 1-60 days)
- Runs on schedule (daily, weekly, monthly, or when disk space is low)
- Respects "Always keep on this device" settings

### Key Points:
- NOT required for Files On-Demand to work
- Automates the "Free up space" action
- Configured through Windows Settings or Group Policy
- Complements Files On-Demand for hands-free disk management

## How They Work Together

```
Files On-Demand (Always On)          Storage Sense (Optional)
       |                                     |
       v                                     v
[All files visible]              [Monitors file usage]
       |                                     |
       v                                     v
[Manual control]                 [Automatic conversion]
- Right-click menu               - Unused files → online-only
- User decides                   - Based on schedule/threshold
```

## Configuration Matrix

| Scenario | Files On-Demand | Storage Sense | Result |
|----------|----------------|---------------|---------|
| Minimal | ✓ Enabled | ✗ Disabled | Manual space management only |
| Optimal | ✓ Enabled | ✓ Enabled | Automatic + manual management |
| Legacy | ✗ Disabled | N/A | All files use disk space |

## RMM Implementation

### Detection Priority:
1. **Critical**: OneDrive installed, running, KFM configured
2. **Critical**: Files On-Demand enabled (or version 23.066+)
3. **Recommended**: Storage Sense configured for automation

### Remediation Strategy:
1. Always configure Files On-Demand (though it's on by default)
2. Configure Storage Sense for optimal user experience
3. Set reasonable defaults (30 days is standard)
4. Document manual options for users

## Registry Keys

### Files On-Demand:
```
HKLM:\SOFTWARE\Policies\Microsoft\OneDrive
- FilesOnDemandEnabled = 1
```

### Storage Sense:
```
HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense
- AllowStorageSenseGlobal = 1
- ConfigStorageSenseGlobalCadence = 7 (weekly)
- ConfigStorageSenseCloudContentDehydrationThreshold = 30 (days)
```

## User Experience

### With Files On-Demand only:
- See all files immediately
- Manually choose what to keep locally
- Right-click to free up space when needed

### With Files On-Demand + Storage Sense:
- See all files immediately
- Frequently used files stay local automatically
- Unused files convert to online-only automatically
- Can still manually override with "Always keep on this device"

## Best Practices

1. **Always enable Files On-Demand** (though it's default now)
2. **Enable Storage Sense** for hands-free management
3. **Set reasonable thresholds** (30 days is good default)
4. **Educate users** about right-click options
5. **Exclude critical files** (.pst, .ost) from sync

## Troubleshooting

### Files not converting to online-only:
- Check Storage Sense is enabled
- Verify threshold settings
- Check if files are marked "Always keep on this device"
- Ensure OneDrive sync is healthy

### Too aggressive conversion:
- Increase days threshold in Storage Sense
- Mark important files as "Always keep on this device"
- Adjust Storage Sense cadence

## Summary
Files On-Demand provides the capability, Storage Sense provides the automation. Together, they create an optimal disk space management solution for Windows 11 upgrades.