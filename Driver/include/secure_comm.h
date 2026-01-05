#pragma once

#include <ntddk.h>

//
// KernelEye Driver - Secure Communication Module
// Provides encryption and authentication for driver/user-mode communication
//

// Authentication status
typedef enum _AUTH_STATUS {
    AuthSuccess = 0,
    AuthFailed,
    AuthExpired,
    AuthInvalid,
    AuthUnknown
} AUTH_STATUS;

// Session state
typedef struct _SECURE_SESSION {
    LIST_ENTRY ListEntry;
    
    UINT64 SessionId;
    UINT64 ProcessId;
    
    BYTE SessionKey[32];        // AES-256 key
    BYTE IV[16];                // Initialization vector
    
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER ExpirationTime;
    LARGE_INTEGER LastActivity;
    
    UINT32 RequestCount;
    UINT32 SequenceNumber;
    
    BOOLEAN IsAuthenticated;
    BOOLEAN IsActive;
} SECURE_SESSION, *PSECURE_SESSION;

// Secure communication state
typedef struct _SECURE_COMM_STATE {
    BOOLEAN Initialized;
    BOOLEAN EncryptionEnabled;
    
    LIST_ENTRY SessionList;
    KSPIN_LOCK SessionLock;
    UINT32 ActiveSessions;
    
    // Master key for key derivation
    BYTE MasterKey[32];
    
    // Rate limiting
    UINT32 MaxRequestsPerMinute;
    LARGE_INTEGER RateLimitWindow;
    
    // Statistics
    UINT64 TotalRequests;
    UINT64 AuthenticatedRequests;
    UINT64 RejectedRequests;
    UINT64 EncryptedBytes;
} SECURE_COMM_STATE, *PSECURE_COMM_STATE;

// Encrypted message header
typedef struct _ENCRYPTED_MESSAGE_HEADER {
    UINT32 Magic;               // 'SKEY'
    UINT32 Version;
    UINT64 SessionId;
    UINT32 SequenceNumber;
    UINT32 EncryptedSize;
    BYTE IV[16];
    BYTE HMAC[32];              // SHA-256 HMAC
} ENCRYPTED_MESSAGE_HEADER, *PENCRYPTED_MESSAGE_HEADER;

// Authentication request
typedef struct _AUTH_REQUEST {
    UINT64 ProcessId;
    UINT64 Timestamp;
    BYTE Challenge[32];
} AUTH_REQUEST, *PAUTH_REQUEST;

// Authentication response
typedef struct _AUTH_RESPONSE {
    UINT64 SessionId;
    LARGE_INTEGER ExpirationTime;
    BYTE SessionKey[32];
    AUTH_STATUS Status;
} AUTH_RESPONSE, *PAUTH_RESPONSE;

// Initialize/cleanup
NTSTATUS SecureCommInitialize(VOID);
VOID SecureCommCleanup(VOID);

// Session management
NTSTATUS CreateSecureSession(_In_ UINT64 ProcessId, _Out_ PSECURE_SESSION* Session);
NTSTATUS DestroySecureSession(_In_ UINT64 SessionId);
PSECURE_SESSION FindSessionById(_In_ UINT64 SessionId);
PSECURE_SESSION FindSessionByProcessId(_In_ UINT64 ProcessId);
BOOLEAN IsSessionValid(_In_ PSECURE_SESSION Session);
NTSTATUS RefreshSession(_In_ PSECURE_SESSION Session);

// Authentication
NTSTATUS AuthenticateClient(_In_ PAUTH_REQUEST Request, _Out_ PAUTH_RESPONSE Response);
NTSTATUS ValidateSessionToken(_In_ UINT64 SessionId, _In_ UINT32 SequenceNumber);
NTSTATUS RevokeAuthentication(_In_ UINT64 ProcessId);

// Encryption/Decryption
NTSTATUS EncryptMessage(
    _In_ PSECURE_SESSION Session,
    _In_ PVOID PlainData,
    _In_ ULONG PlainDataSize,
    _Out_ PVOID EncryptedData,
    _In_ ULONG EncryptedBufferSize,
    _Out_ PULONG EncryptedDataSize
);

NTSTATUS DecryptMessage(
    _In_ PSECURE_SESSION Session,
    _In_ PVOID EncryptedData,
    _In_ ULONG EncryptedDataSize,
    _Out_ PVOID PlainData,
    _In_ ULONG PlainBufferSize,
    _Out_ PULONG PlainDataSize
);

// Integrity checking
NTSTATUS CalculateHMAC(
    _In_ PVOID Data,
    _In_ ULONG DataSize,
    _In_ PVOID Key,
    _In_ ULONG KeySize,
    _Out_ BYTE HMAC[32]
);

BOOLEAN VerifyHMAC(
    _In_ PVOID Data,
    _In_ ULONG DataSize,
    _In_ PVOID Key,
    _In_ ULONG KeySize,
    _In_ BYTE ExpectedHMAC[32]
);

// Rate limiting
BOOLEAN CheckRateLimit(_In_ UINT64 ProcessId);
NTSTATUS ResetRateLimit(_In_ UINT64 ProcessId);

// Key management
NTSTATUS GenerateSessionKey(_Out_ BYTE Key[32]);
NTSTATUS DeriveKey(_In_ PVOID MasterKey, _In_ UINT64 SessionId, _Out_ BYTE DerivedKey[32]);

// Statistics
NTSTATUS GetSecureCommStatistics(
    _Out_ PUINT64 TotalRequests,
    _Out_ PUINT64 AuthenticatedRequests,
    _Out_ PUINT64 RejectedRequests,
    _Out_ PUINT32 ActiveSessions
);
