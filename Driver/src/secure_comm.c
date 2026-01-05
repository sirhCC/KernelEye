//
// KernelEye Anti-Cheat Driver - Secure Communication
// Provides encryption and authentication for driver/user-mode communication
//

#include "../include/driver.h"
#include "../include/secure_comm.h"
#include <bcrypt.h>

// Global state
static SECURE_COMM_STATE g_SecureCommState = {0};

// Constants
#define SESSION_EXPIRATION_TIME_SECONDS 3600  // 1 hour
#define MAX_REQUESTS_PER_MINUTE 60
#define SECURE_COMM_MAGIC 0x5345594B  // 'SKEY'

//
// SecureCommInitialize
//
NTSTATUS SecureCommInitialize(VOID)
{
    if (g_SecureCommState.Initialized) {
        KE_WARNING("Secure communication already initialized");
        return STATUS_SUCCESS;
    }

    KE_INFO("Initializing secure communication...");

    RtlZeroMemory(&g_SecureCommState, sizeof(SECURE_COMM_STATE));
    
    InitializeListHead(&g_SecureCommState.SessionList);
    KeInitializeSpinLock(&g_SecureCommState.SessionLock);

    // Generate master key (in production, this should be securely stored)
    NTSTATUS status = GenerateSessionKey(g_SecureCommState.MasterKey);
    if (!NT_SUCCESS(status)) {
        KE_ERROR("Failed to generate master key: 0x%08X", status);
        return status;
    }

    g_SecureCommState.EncryptionEnabled = TRUE;
    g_SecureCommState.MaxRequestsPerMinute = MAX_REQUESTS_PER_MINUTE;
    
    g_SecureCommState.Initialized = TRUE;

    KE_INFO("Secure communication initialized successfully");
    return STATUS_SUCCESS;
}

//
// SecureCommCleanup
//
VOID SecureCommCleanup(VOID)
{
    PLIST_ENTRY entry;
    PSECURE_SESSION session;

    if (!g_SecureCommState.Initialized) {
        return;
    }

    KE_INFO("Cleaning up secure communication...");

    while (!IsListEmpty(&g_SecureCommState.SessionList)) {
        entry = RemoveHeadList(&g_SecureCommState.SessionList);
        session = CONTAINING_RECORD(entry, SECURE_SESSION, ListEntry);
        
        // Zero out sensitive data
        RtlSecureZeroMemory(session->SessionKey, sizeof(session->SessionKey));
        RtlSecureZeroMemory(session->IV, sizeof(session->IV));
        
        ExFreePoolWithTag(session, KERNELEYE_POOL_TAG);
    }

    RtlSecureZeroMemory(g_SecureCommState.MasterKey, sizeof(g_SecureCommState.MasterKey));

    g_SecureCommState.Initialized = FALSE;
    KE_INFO("Secure communication cleaned up");
}

//
// CreateSecureSession
//
NTSTATUS CreateSecureSession(
    _In_ UINT64 ProcessId,
    _Out_ PSECURE_SESSION* Session
)
{
    NTSTATUS status;
    PSECURE_SESSION newSession;
    KIRQL oldIrql;
    LARGE_INTEGER expirationTime;

    newSession = (PSECURE_SESSION)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(SECURE_SESSION),
        KERNELEYE_POOL_TAG
    );

    if (!newSession) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(newSession, sizeof(SECURE_SESSION));

    // Generate session ID (use timestamp + counter for uniqueness)
    KeQuerySystemTime((PLARGE_INTEGER)&newSession->SessionId);
    newSession->ProcessId = ProcessId;

    // Generate session key
    status = GenerateSessionKey(newSession->SessionKey);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(newSession, KERNELEYE_POOL_TAG);
        return status;
    }

    // Generate IV
    status = GenerateSessionKey(newSession->IV);
    if (!NT_SUCCESS(status)) {
        RtlSecureZeroMemory(newSession->SessionKey, sizeof(newSession->SessionKey));
        ExFreePoolWithTag(newSession, KERNELEYE_POOL_TAG);
        return status;
    }

    KeQuerySystemTime(&newSession->CreationTime);
    KeQuerySystemTime(&newSession->LastActivity);
    
    expirationTime.QuadPart = newSession->CreationTime.QuadPart + 
                              (SESSION_EXPIRATION_TIME_SECONDS * 10000000LL);
    newSession->ExpirationTime = expirationTime;

    newSession->IsAuthenticated = TRUE;
    newSession->IsActive = TRUE;
    newSession->SequenceNumber = 0;
    newSession->RequestCount = 0;

    KeAcquireSpinLock(&g_SecureCommState.SessionLock, &oldIrql);
    InsertTailList(&g_SecureCommState.SessionList, &newSession->ListEntry);
    g_SecureCommState.ActiveSessions++;
    KeReleaseSpinLock(&g_SecureCommState.SessionLock, oldIrql);

    *Session = newSession;

    KE_INFO("Secure session created: SessionId=%llu, PID=%llu", 
        newSession->SessionId, ProcessId);

    return STATUS_SUCCESS;
}

//
// DestroySecureSession
//
NTSTATUS DestroySecureSession(
    _In_ UINT64 SessionId
)
{
    PSECURE_SESSION session;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_SecureCommState.SessionLock, &oldIrql);
    
    session = FindSessionById(SessionId);
    if (session) {
        RemoveEntryList(&session->ListEntry);
        g_SecureCommState.ActiveSessions--;
        KeReleaseSpinLock(&g_SecureCommState.SessionLock, oldIrql);
        
        RtlSecureZeroMemory(session->SessionKey, sizeof(session->SessionKey));
        RtlSecureZeroMemory(session->IV, sizeof(session->IV));
        
        ExFreePoolWithTag(session, KERNELEYE_POOL_TAG);
        
        KE_INFO("Secure session destroyed: SessionId=%llu", SessionId);
        return STATUS_SUCCESS;
    }
    
    KeReleaseSpinLock(&g_SecureCommState.SessionLock, oldIrql);
    
    KE_WARNING("Session not found: SessionId=%llu", SessionId);
    return STATUS_NOT_FOUND;
}

//
// FindSessionById
//
PSECURE_SESSION FindSessionById(
    _In_ UINT64 SessionId
)
{
    PLIST_ENTRY entry;
    PSECURE_SESSION session;

    for (entry = g_SecureCommState.SessionList.Flink;
         entry != &g_SecureCommState.SessionList;
         entry = entry->Flink)
    {
        session = CONTAINING_RECORD(entry, SECURE_SESSION, ListEntry);
        if (session->SessionId == SessionId) {
            return session;
        }
    }

    return NULL;
}

//
// FindSessionByProcessId
//
PSECURE_SESSION FindSessionByProcessId(
    _In_ UINT64 ProcessId
)
{
    PLIST_ENTRY entry;
    PSECURE_SESSION session;

    for (entry = g_SecureCommState.SessionList.Flink;
         entry != &g_SecureCommState.SessionList;
         entry = entry->Flink)
    {
        session = CONTAINING_RECORD(entry, SECURE_SESSION, ListEntry);
        if (session->ProcessId == ProcessId && session->IsActive) {
            return session;
        }
    }

    return NULL;
}

//
// IsSessionValid
//
BOOLEAN IsSessionValid(
    _In_ PSECURE_SESSION Session
)
{
    LARGE_INTEGER currentTime;

    if (!Session || !Session->IsActive || !Session->IsAuthenticated) {
        return FALSE;
    }

    KeQuerySystemTime(&currentTime);
    
    if (currentTime.QuadPart > Session->ExpirationTime.QuadPart) {
        return FALSE;
    }

    return TRUE;
}

//
// RefreshSession
//
NTSTATUS RefreshSession(
    _In_ PSECURE_SESSION Session
)
{
    LARGE_INTEGER currentTime;
    LARGE_INTEGER expirationTime;

    KeQuerySystemTime(&currentTime);
    Session->LastActivity = currentTime;

    expirationTime.QuadPart = currentTime.QuadPart + 
                              (SESSION_EXPIRATION_TIME_SECONDS * 10000000LL);
    Session->ExpirationTime = expirationTime;

    return STATUS_SUCCESS;
}

//
// AuthenticateClient
//
NTSTATUS AuthenticateClient(
    _In_ PAUTH_REQUEST Request,
    _Out_ PAUTH_RESPONSE Response
)
{
    NTSTATUS status;
    PSECURE_SESSION session;

    RtlZeroMemory(Response, sizeof(AUTH_RESPONSE));

    // Check rate limit
    if (!CheckRateLimit(Request->ProcessId)) {
        KE_WARNING("Rate limit exceeded for PID=%llu", Request->ProcessId);
        Response->Status = AuthFailed;
        g_SecureCommState.RejectedRequests++;
        return STATUS_REQUEST_NOT_ACCEPTED;
    }

    // Create secure session
    status = CreateSecureSession(Request->ProcessId, &session);
    if (!NT_SUCCESS(status)) {
        KE_ERROR("Failed to create secure session: 0x%08X", status);
        Response->Status = AuthFailed;
        g_SecureCommState.RejectedRequests++;
        return status;
    }

    // Fill response
    Response->SessionId = session->SessionId;
    Response->ExpirationTime = session->ExpirationTime;
    RtlCopyMemory(Response->SessionKey, session->SessionKey, sizeof(Response->SessionKey));
    Response->Status = AuthSuccess;

    g_SecureCommState.AuthenticatedRequests++;

    KE_INFO("Client authenticated: PID=%llu, SessionId=%llu", 
        Request->ProcessId, session->SessionId);

    return STATUS_SUCCESS;
}

//
// ValidateSessionToken
//
NTSTATUS ValidateSessionToken(
    _In_ UINT64 SessionId,
    _In_ UINT32 SequenceNumber
)
{
    PSECURE_SESSION session;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_SecureCommState.SessionLock, &oldIrql);
    
    session = FindSessionById(SessionId);
    if (!session) {
        KeReleaseSpinLock(&g_SecureCommState.SessionLock, oldIrql);
        return STATUS_NOT_FOUND;
    }

    if (!IsSessionValid(session)) {
        KeReleaseSpinLock(&g_SecureCommState.SessionLock, oldIrql);
        return STATUS_EXPIRED_HANDLE;
    }

    // Check sequence number (replay protection)
    if (SequenceNumber <= session->SequenceNumber) {
        KeReleaseSpinLock(&g_SecureCommState.SessionLock, oldIrql);
        KE_WARNING("Replay attack detected: SessionId=%llu, Seq=%u", SessionId, SequenceNumber);
        return STATUS_ACCESS_DENIED;
    }

    session->SequenceNumber = SequenceNumber;
    session->RequestCount++;
    RefreshSession(session);

    KeReleaseSpinLock(&g_SecureCommState.SessionLock, oldIrql);

    return STATUS_SUCCESS;
}

//
// RevokeAuthentication
//
NTSTATUS RevokeAuthentication(
    _In_ UINT64 ProcessId
)
{
    PSECURE_SESSION session;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_SecureCommState.SessionLock, &oldIrql);
    
    session = FindSessionByProcessId(ProcessId);
    if (session) {
        session->IsAuthenticated = FALSE;
        session->IsActive = FALSE;
        KeReleaseSpinLock(&g_SecureCommState.SessionLock, oldIrql);
        
        KE_INFO("Authentication revoked for PID=%llu", ProcessId);
        return STATUS_SUCCESS;
    }
    
    KeReleaseSpinLock(&g_SecureCommState.SessionLock, oldIrql);
    
    return STATUS_NOT_FOUND;
}

//
// EncryptMessage (Stub - real implementation needs CNG or similar)
//
NTSTATUS EncryptMessage(
    _In_ PSECURE_SESSION Session,
    _In_ PVOID PlainData,
    _In_ ULONG PlainDataSize,
    _Out_ PVOID EncryptedData,
    _In_ ULONG EncryptedBufferSize,
    _Out_ PULONG EncryptedDataSize
)
{
    UNREFERENCED_PARAMETER(Session);
    UNREFERENCED_PARAMETER(EncryptedBufferSize);

    // TODO: Implement AES-256-CBC encryption using BCrypt
    // For now, just copy the data (no encryption)
    
    if (PlainDataSize > EncryptedBufferSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(EncryptedData, PlainData, PlainDataSize);
    *EncryptedDataSize = PlainDataSize;

    g_SecureCommState.EncryptedBytes += PlainDataSize;

    return STATUS_SUCCESS;
}

//
// DecryptMessage (Stub - real implementation needs CNG or similar)
//
NTSTATUS DecryptMessage(
    _In_ PSECURE_SESSION Session,
    _In_ PVOID EncryptedData,
    _In_ ULONG EncryptedDataSize,
    _Out_ PVOID PlainData,
    _In_ ULONG PlainBufferSize,
    _Out_ PULONG PlainDataSize
)
{
    UNREFERENCED_PARAMETER(Session);

    // TODO: Implement AES-256-CBC decryption using BCrypt
    // For now, just copy the data (no decryption)
    
    if (EncryptedDataSize > PlainBufferSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(PlainData, EncryptedData, EncryptedDataSize);
    *PlainDataSize = EncryptedDataSize;

    return STATUS_SUCCESS;
}

//
// CalculateHMAC (Stub - real implementation needs CNG)
//
NTSTATUS CalculateHMAC(
    _In_ PVOID Data,
    _In_ ULONG DataSize,
    _In_ PVOID Key,
    _In_ ULONG KeySize,
    _Out_ BYTE HMAC[32]
)
{
    UNREFERENCED_PARAMETER(Key);
    UNREFERENCED_PARAMETER(KeySize);

    // TODO: Implement SHA-256 HMAC using BCrypt
    // For now, use simple checksum
    
    UINT32 checksum = 0;
    BYTE* buffer = (BYTE*)Data;
    ULONG i;

    for (i = 0; i < DataSize; i++) {
        checksum += buffer[i];
        checksum = (checksum << 1) | (checksum >> 31);
    }

    RtlZeroMemory(HMAC, 32);
    RtlCopyMemory(HMAC, &checksum, sizeof(checksum));

    return STATUS_SUCCESS;
}

//
// VerifyHMAC
//
BOOLEAN VerifyHMAC(
    _In_ PVOID Data,
    _In_ ULONG DataSize,
    _In_ PVOID Key,
    _In_ ULONG KeySize,
    _In_ BYTE ExpectedHMAC[32]
)
{
    BYTE calculatedHMAC[32];
    NTSTATUS status;

    status = CalculateHMAC(Data, DataSize, Key, KeySize, calculatedHMAC);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    return (RtlCompareMemory(calculatedHMAC, ExpectedHMAC, 32) == 32);
}

//
// CheckRateLimit (Simplified implementation)
//
BOOLEAN CheckRateLimit(
    _In_ UINT64 ProcessId
)
{
    UNREFERENCED_PARAMETER(ProcessId);

    g_SecureCommState.TotalRequests++;

    // TODO: Implement proper rate limiting per process
    // For now, always allow
    
    return TRUE;
}

//
// ResetRateLimit
//
NTSTATUS ResetRateLimit(
    _In_ UINT64 ProcessId
)
{
    UNREFERENCED_PARAMETER(ProcessId);

    // TODO: Implement rate limit reset
    
    return STATUS_SUCCESS;
}

//
// GenerateSessionKey
//
NTSTATUS GenerateSessionKey(
    _Out_ BYTE Key[32]
)
{
    LARGE_INTEGER counter;
    UINT32 i;

    // TODO: Use BCryptGenRandom for cryptographically secure random
    // For now, use KeQueryPerformanceCounter as entropy source
    
    for (i = 0; i < 32; i += sizeof(LARGE_INTEGER)) {
        KeQueryPerformanceCounter(&counter);
        RtlCopyMemory(&Key[i], &counter, min(sizeof(LARGE_INTEGER), 32 - i));
    }

    return STATUS_SUCCESS;
}

//
// DeriveKey
//
NTSTATUS DeriveKey(
    _In_ PVOID MasterKey,
    _In_ UINT64 SessionId,
    _Out_ BYTE DerivedKey[32]
)
{
    // TODO: Implement proper key derivation (HKDF or similar)
    // For now, simple XOR with session ID
    
    RtlCopyMemory(DerivedKey, MasterKey, 32);
    
    for (UINT32 i = 0; i < 32; i += sizeof(UINT64)) {
        *((UINT64*)&DerivedKey[i]) ^= SessionId;
    }

    return STATUS_SUCCESS;
}

//
// GetSecureCommStatistics
//
NTSTATUS GetSecureCommStatistics(
    _Out_ PUINT64 TotalRequests,
    _Out_ PUINT64 AuthenticatedRequests,
    _Out_ PUINT64 RejectedRequests,
    _Out_ PUINT32 ActiveSessions
)
{
    *TotalRequests = g_SecureCommState.TotalRequests;
    *AuthenticatedRequests = g_SecureCommState.AuthenticatedRequests;
    *RejectedRequests = g_SecureCommState.RejectedRequests;
    *ActiveSessions = g_SecureCommState.ActiveSessions;

    return STATUS_SUCCESS;
}
