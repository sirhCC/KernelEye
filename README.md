# KernelEye Anti-Cheat System

A comprehensive kernel-level anti-cheat system for detecting and preventing game cheating through memory manipulation, code injection, driver-based attacks, and behavioral anomalies.

## Project Status

**Phase 1: Foundation - IN PROGRESS**

✅ Complete project structure  
✅ Common headers and protocols  
✅ Kernel driver foundation  
✅ IOCTL communication layer  
✅ User-mode service skeleton  
✅ Build configuration

## Components

### KernelEye.sys (Kernel Driver)
- Device object and symbolic link creation
- IOCTL communication interface
- Version management
- Statistics tracking
- Heartbeat monitoring

### KernelEyeService.exe (User-Mode Service)
- Driver communication interface
- Logging system
- Heartbeat management
- Statistics monitoring

### Shared Components
- Protocol definitions
- Data structures
- Constants and configuration

## Building

### Prerequisites
- Windows 10/11 x64
- Visual Studio 2022 with WDK
- Windows SDK 10.0.22621.0 or later
- Windows Driver Kit 10.0.22621.0 or later

### Build Steps

1. **Install WDK**
   - Download and install the Windows Driver Kit from Microsoft

2. **Open Solution**
   ```
   Open KernelEye.sln in Visual Studio 2022
   ```

3. **Build Driver**
   - Set configuration to Debug|x64
   - Build the KernelEye project
   - Output: `bin\x64\Debug\KernelEye.sys`

4. **Build Service**
   - Build the KernelEyeService project
   - Output: `bin\x64\Debug\KernelEyeService.exe`

## Testing (Development)

### Enable Test Signing Mode
```powershell
# Run as Administrator
bcdedit /set testsigning on
# Reboot required
```

### Install Driver
```powershell
# Run as Administrator
sc create KernelEye type= kernel binPath= "C:\Path\To\KernelEye.sys"
sc start KernelEye
```

### Run Service
```powershell
# Run as Administrator
cd bin\x64\Debug
.\KernelEyeService.exe
```

### Uninstall Driver
```powershell
# Run as Administrator
sc stop KernelEye
sc delete KernelEye
```

## Architecture

```
Game Process
    ↓ (behavioral data)
KernelEyeClient.dll (TODO)
    ↓ (reports, heartbeat)
KernelEyeService.exe
    ↓ (IOCTL requests)
KernelEye.sys (Driver)
    ↓ (scan results, detections)
KernelEyeService.exe
    ↓ (aggregated reports)
Game Server / Admin Panel (TODO)
```

## Current Capabilities

### Driver
- [x] Device and symbolic link creation
- [x] IOCTL handler infrastructure
- [x] Version reporting
- [x] Statistics tracking
- [x] Heartbeat processing
- [x] Initialization/shutdown
- [ ] Memory scanning
- [ ] Hook detection
- [ ] Process protection
- [ ] Driver verification

### Service
- [x] Driver connection management
- [x] Version checking
- [x] Statistics retrieval
- [x] Heartbeat sending
- [x] Logging system
- [ ] Configuration management
- [ ] Detection reporting
- [ ] Scan requests

## Next Steps

**Phase 2: Memory Scanner (Weeks 3-4)**
- Process memory enumeration
- VAD tree walking
- Page protection scanning
- PE header validation
- Code integrity checks

See [PROJECT_ARCHITECTURE.md](PROJECT_ARCHITECTURE.md) for complete roadmap.

## Development Notes

### Debug Output
- Driver debug output visible in DebugView or WinDbg
- Service output logged to `KernelEyeService.log`

### Important Warnings
- This is development code - **NOT production ready**
- Test signing mode reduces system security
- Only test on dedicated development machines
- Driver bugs can cause BSOD - use VMs for testing
- Requires administrator privileges

## Security Considerations

⚠️ **This is a work in progress**
- No encryption implemented yet (Phase 6)
- No self-protection mechanisms (Phase 10)
- No cheat detection logic (Phases 2-5, 7-9)
- Simple checksum instead of HMAC

## License

Copyright (c) 2026 KernelEye Project  
**Proprietary - All Rights Reserved**

## Documentation

- [PROJECT_ARCHITECTURE.md](PROJECT_ARCHITECTURE.md) - Complete system architecture
- [Docs/API.md](Docs/API.md) - API documentation (TODO)
- [Docs/PROTOCOLS.md](Docs/PROTOCOLS.md) - Communication protocols (TODO)
- [Docs/DEPLOYMENT.md](Docs/DEPLOYMENT.md) - Deployment guide (TODO)

## Support

This is an active development project. For issues or questions:
- Review PROJECT_ARCHITECTURE.md for design decisions
- Check debug logs for error messages
- Ensure test signing mode is enabled
- Verify WDK installation

---

**Version**: 1.0.0.1  
**Last Updated**: January 4, 2026  
**Status**: Phase 1 Complete - Foundation Ready
