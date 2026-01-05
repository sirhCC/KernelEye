# KernelEye Testing Guide

## Prerequisites

### Required Software
- ✅ Windows 10/11 x64 (Build 19041 or later)
- ✅ Visual Studio 2022 with:
  - Desktop development with C++
  - Windows Driver Kit (WDK) 10.0.22621.0+
- ✅ Administrator privileges

### System Preparation

**1. Enable Test Signing Mode** (Required for unsigned driver)
```powershell
# Run PowerShell as Administrator
bcdedit /set testsigning on

# Reboot system
shutdown /r /t 0
```

**Warning**: Test signing reduces security. Only use on development/test machines.

**2. Verify Test Signing is Enabled**
```powershell
bcdedit /enum {current}
# Look for "testsigning Yes"
```

---

## Building the Project

### Option 1: Visual Studio GUI

1. Open `KernelEye.sln` in Visual Studio 2022
2. Select **Debug | x64** configuration
3. Build → Build Solution (Ctrl+Shift+B)
4. Check Output window for build results

### Option 2: Command Line (MSBuild)

```powershell
# Open "Developer Command Prompt for VS 2022" or "x64 Native Tools Command Prompt"

# Navigate to project directory
cd D:\KernelEye

# Build driver
msbuild Driver\KernelEye.vcxproj /p:Configuration=Debug /p:Platform=x64

# Build service
msbuild Service\KernelEyeService.vcxproj /p:Configuration=Debug /p:Platform=x64
```

### Expected Output
```
bin\
  x64\
    Debug\
      KernelEye.sys     - Kernel driver
      KernelEye.inf     - Driver installation file
      KernelEyeService.exe - User-mode service
```

---

## Installing and Running

### Step 1: Create Driver Service

```powershell
# Run as Administrator
cd D:\KernelEye\bin\x64\Debug

# Create service
sc create KernelEye type= kernel binPath= "%CD%\KernelEye.sys"

# Expected: [SC] CreateService SUCCESS
```

### Step 2: Start Driver

```powershell
# Start the driver
sc start KernelEye

# Check status
sc query KernelEye

# Expected output:
# STATE              : 4  RUNNING
```

### Step 3: Run Service

```powershell
# In same directory
.\KernelEyeService.exe
```

### Expected Service Output
```
[2026-01-04 10:30:15.123] [INFO ] === KernelEye Service Started ===
[2026-01-04 10:30:15.125] [INFO ] KernelEye Service starting...
[2026-01-04 10:30:15.126] [INFO ] Version: 1.0.0.1
[2026-01-04 10:30:15.130] [INFO ] Connecting to driver: \\.\KernelEye
[2026-01-04 10:30:15.135] [INFO ] Successfully connected to driver
[2026-01-04 10:30:15.140] [INFO ] Driver version: 1.0.0.1
[2026-01-04 10:30:15.145] [INFO ] Initializing driver
[2026-01-04 10:30:15.150] [INFO ] Driver initialized successfully
[2026-01-04 10:30:15.151] [INFO ] Service is running. Press Ctrl+C to stop.
```

---

## Testing Memory Scanner

### Method 1: Using Test Utility (Recommended)

Create a test program that exercises the memory scanner:

```powershell
# Build the test utility first (see below)
cd D:\KernelEye\bin\x64\Debug

# Run test
.\MemoryScanTest.exe
```

### Method 2: Manual Testing with PowerShell

Monitor the driver debug output while the service runs:

```powershell
# Download and run DebugView as Administrator
# https://learn.microsoft.com/en-us/sysinternals/downloads/debugview

# Or use WinDbg kernel debugging
```

---

## Viewing Debug Output

### Option 1: DebugView (Easiest)

1. Download Sysinternals DebugView
2. Run as Administrator
3. Capture → Capture Kernel
4. You'll see driver output like:
   ```
   [KernelEye:DriverEntry:45] KernelEye driver loading...
   [KernelEye:DriverEntry:46] Version: 1.0.0.1
   [KernelEye:MemoryScannerInitialize:15] Initializing memory scanner...
   ```

### Option 2: WinDbg Kernel Debugging

For advanced debugging (optional):
```powershell
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
```

---

## Testing Checklist

### Basic Functionality Tests

- [ ] **Build succeeds** without errors
- [ ] **Driver loads** successfully (sc start succeeds)
- [ ] **Service connects** to driver
- [ ] **Version check** returns 1.0.0.1
- [ ] **Driver initializes** without errors
- [ ] **Heartbeat** messages appear every 5 seconds
- [ ] **Statistics** can be retrieved
- [ ] **Service shuts down** cleanly with Ctrl+C

### Memory Scanner Tests

- [ ] **Memory scan** completes without BSOD
- [ ] **VAD enumeration** works on test process
- [ ] **Detections** are reported for suspicious memory
- [ ] **Driver logs** show scan progress
- [ ] **Service receives** scan results

---

## Common Issues and Solutions

### Issue: "sc start KernelEye" fails with error 577

**Cause**: Driver not signed / test signing not enabled

**Solution**:
```powershell
bcdedit /set testsigning on
shutdown /r /t 0
```

### Issue: "sc start KernelEye" fails with error 1275

**Cause**: Driver signature invalid

**Solution**: Verify WDK build produced .sys file correctly

### Issue: Service can't connect to driver (Error 0x00000002)

**Cause**: Driver not running

**Solution**:
```powershell
sc query KernelEye
# If not running, check driver logs with DebugView
```

### Issue: System BSOD when running memory scan

**Cause**: VAD tree offset incorrect for your Windows version

**Solution**: 
- Only test on Windows 10/11 64-bit
- VAD offset in GetProcessVadRoot() may need adjustment
- Use safe test processes (notepad.exe)

### Issue: DebugView shows no output

**Solution**:
```powershell
# Enable verbose kernel debugging
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter" /v DEFAULT /t REG_DWORD /d 0xF
```

---

## Stopping and Cleanup

### Stop Service
```powershell
# Press Ctrl+C in service window
```

### Stop and Remove Driver
```powershell
# Stop driver
sc stop KernelEye

# Delete service
sc delete KernelEye

# Verify removed
sc query KernelEye
# Expected: The specified service does not exist
```

### Disable Test Signing (Optional)
```powershell
bcdedit /set testsigning off
shutdown /r /t 0
```

---

## Expected Behavior

### Normal Operation

1. **Driver loads** without errors
2. **Service connects** and initializes driver
3. **Heartbeats** sent every 5 seconds
4. **Memory scans** complete in < 5 seconds per process
5. **No system crashes** or freezes
6. **Clean shutdown** when stopping service

### Debug Output Example

```
[KernelEye:DriverEntry] KernelEye driver loading...
[KernelEye:DriverEntry] Version: 1.0.0.1
[KernelEye:DriverEntry] Device object created successfully
[KernelEye:DriverEntry] Symbolic link created successfully
[KernelEye:DriverEntry] KernelEye driver loaded successfully
[KernelEye:HandleInitialize] HandleInitialize called
[KernelEye:MemoryScannerInitialize] Initializing memory scanner...
[KernelEye:MemoryScannerInitialize] Memory scanner initialized successfully
[KernelEye:HandleHeartbeat] Heartbeat received from PID: 12345, Sequence: 1
[KernelEye:HandleCheckMemory] HandleCheckMemory called
[KernelEye:ScanProcessMemory] Scanning process memory: PID=12345, Flags=0x00000001
[KernelEye:ScanProcessMemory] Memory scan complete: 245 regions, 12 suspicious, 3 detections
```

---

## Performance Metrics

### Expected Performance
- **Driver startup**: < 100ms
- **Service connection**: < 50ms
- **Heartbeat latency**: < 1ms
- **Memory scan** (typical process): 1-3 seconds
- **Memory scan** (large process): 3-10 seconds
- **CPU usage** (idle): < 0.1%
- **CPU usage** (scanning): 2-5%
- **Memory usage**: 5-15 MB

---

## Safety Tips

⚠️ **IMPORTANT SAFETY GUIDELINES**

1. **Use Virtual Machine** for initial testing
2. **Save all work** before loading driver
3. **Expect BSODs** during development
4. **Don't test on production** systems
5. **Keep backup** of working driver versions
6. **Monitor memory usage** - watch for leaks
7. **Use safe test processes** (notepad.exe, not critical system processes)

---

## Next Steps After Testing

Once basic tests pass:
1. ✅ Verify driver loads and runs stable
2. ✅ Test memory scanner on simple processes
3. ✅ Review debug output for errors
4. ✅ Fix any crashes or issues
5. ➡️ Proceed to Phase 3 (Hook Detection)

---

## Getting Help

If you encounter issues:
1. Check **DebugView** output for error messages
2. Review **Event Viewer** → Windows Logs → System for driver errors
3. Check **KernelEyeService.log** for service errors
4. Verify all prerequisites are installed
5. Ensure test signing is enabled

**Current Status**: Phase 2 Complete - Ready for Testing
**Version**: 1.0.0.1
**Last Updated**: January 4, 2026
