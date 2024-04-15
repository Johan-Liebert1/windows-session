#include <windows.h>
#include <ntsecapi.h>
#include <ntstatus.h>
#include <stdio.h>

void PrintLastError(char *funcName) {
    // Get the error message ID, if any.
    DWORD errorMessageID = GetLastError();

    LPSTR messageBuffer = NULL;

    // Ask Win32 to give us the string version of that message ID.
    // The parameters we pass in, tell Win32 to create the buffer that holds
    // the message for us (because we don't yet know how long the message
    // string will be).
    size_t size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&messageBuffer, 0, NULL);

    printf("Size: %lld. %s: %s\n", size, funcName, messageBuffer);

    // Free the Win32's string's buffer.
    LocalFree(messageBuffer);
}

void logonFailureDebug(NTSTATUS status) {
    switch (status) {
    case STATUS_QUOTA_EXCEEDED:
        printf("The caller's memory quota is insufficient to allocate the "
               "output buffer returned by the authentication package.\n");
        break;
    case STATUS_ACCOUNT_RESTRICTION:
        printf("The user account and password are legitimate, but the user "
               "account has a restriction that prevents logon at this time. "
               "For more information, see the value stored in the SubStatus "
               "parameter.\n");
        break;
    case STATUS_BAD_VALIDATION_CLASS:
        printf("The authentication information provided is not recognized by "
               "the authentication package.\n");
        break;
    case STATUS_LOGON_FAILURE:
        printf("The logon attempt failed. The reason for the failure is not "
               "specified, but typical reasons include misspelled user names "
               "and misspelled passwords.\n");
        break;
    case STATUS_NO_LOGON_SERVERS:
        printf("No domain controllers are available to service the "
               "authentication request.\n");
        break;
    case STATUS_NO_SUCH_PACKAGE:
        printf("The specified authentication package is not recognized by the "
               "LSA.\n");
        break;
    case STATUS_PKINIT_FAILURE:
        printf(
            "The Kerberos client received a KDC certificate that is not valid. "
            "For device logon, strict KDC validation is required, so the KDC "
            "must have certificates that use the Kerberos Authentication"
            " template or equivalent. Also, the KDC certificate could be "
            "expired, revoked, or the client is under active attack of sending "
            "requests to the wrong server.\n");
        break;
    case STATUS_PKINIT_CLIENT_FAILURE:
        printf("The Kerberos client is using a system certificate that is not "
               "valid. For device logon, there must be a DNS name. Also, the "
               "system certificate could be expired or the wrong one could be "
               "selected.\n");
        break;
    }
}

HANDLE privelegedLogonProcess() {
    CHAR buffer[] = "User32LogonProcess";

    LSA_STRING string = {
        .MaximumLength = sizeof(buffer),
        .Length = sizeof(buffer) - 1,
        .Buffer = buffer,
    };

    HANDLE registerLogonProcessHandle;
    LSA_OPERATIONAL_MODE securitymode;

    NTSTATUS status = LsaRegisterLogonProcess(
        &string, &registerLogonProcessHandle, &securitymode);

    switch (status) {
    case STATUS_SUCCESS: {
        printf("LsaRegisterLogonProcess Succeeded with status: %ld\n", status);
        break;
    }

    case STATUS_PORT_CONNECTION_REFUSED: {
        printf("LsaRegisterLogonProcess FAILED with status: %ld\n", status);
        printf("The caller does not have the SeTcbPrivilege privilege, which "
               "is required to call this function.");
        printf("You can set this privilege by calling LsaAddAccountRights.\n");
        break;
    }

    case STATUS_NAME_TOO_LONG: {
        printf("LsaRegisterLogonProcess FAILED with status: %ld\n", status);
        printf("The specified logon process name exceeds 127 bytes.\n");
        break;
    }
    }

    return registerLogonProcessHandle;
}

HANDLE nonPrivelegedLogonProcess() {
    HANDLE registerLogonProcessHandle;
    NTSTATUS status = LsaConnectUntrusted(&registerLogonProcessHandle);

    printf("LsaConnectUntrusted return status: %ld\n", status);

    return registerLogonProcessHandle;
}

int main() {
    HANDLE registerLogonProcessHandle = nonPrivelegedLogonProcess();

    if (registerLogonProcessHandle == NULL) {
        printf("nonPrivelegedLogonProcess failed\n");
        return -1;
    }

    printf("registerLogonProcessHandle: %p\n", registerLogonProcessHandle);

    CHAR authPackageName[] = MSV1_0_PACKAGE_NAME;

    LSA_STRING authPackageLsaString = {
        .Length = sizeof(authPackageName) - 1, // Length without null-terminator
        .MaximumLength =
            sizeof(authPackageName), // Maximum length with null-terminator
        .Buffer = authPackageName,
    };

    ULONG authenticationPackage;

    NTSTATUS status = LsaLookupAuthenticationPackage(registerLogonProcessHandle,
                                                     &authPackageLsaString,
                                                     &authenticationPackage);

    switch (status) {
    case STATUS_SUCCESS: {
        printf("LsaLookupAuthenticationPackage Succeeded with status: %ld\n",
               status);
        break;
    }

    case STATUS_NO_SUCH_PACKAGE: {
        printf("LsaLookupAuthenticationPackage FAILED with status: %ld\n",
               status);
        printf("The specified authentication package is unknown to the LSA.\n");
        break;
    }

    case STATUS_NAME_TOO_LONG: {
        printf("LsaLookupAuthenticationPackage FAILED with status: %ld\n",
               status);
        printf("The specified logon process name exceeds 127 bytes.\n");
        break;
    }
    }

    TOKEN_SOURCE tokenUserInformation = {0};
    DWORD returnLen;

    BOOL tokenInfo = GetTokenInformation(
        registerLogonProcessHandle, TokenSource, &tokenUserInformation,
        sizeof(tokenUserInformation), &returnLen);

    if (tokenInfo == 0) {
        PrintLastError("GetTokenInformation");
        printf("GetTokenInformation FAILED AND returned: %d\n", tokenInfo);
    }

    printf("GetTokenInformation returned return len: %ld\n", returnLen);

    PCHAR bufferOriginName = "theft";

    LSA_STRING originString = {
        .MaximumLength = 127,
        .Buffer = bufferOriginName,
    };

    LSA_UNICODE_STRING domainName = {0};

    WCHAR usernameBuffer[] = L"defaultuser";
    LSA_UNICODE_STRING username = {.Length = sizeof(usernameBuffer) - 1,
                                   .MaximumLength = sizeof(usernameBuffer),
                                   .Buffer = usernameBuffer};

    WCHAR passwordBuffer[] = L"passwrod";
    LSA_UNICODE_STRING password = {.Length = sizeof(passwordBuffer) - 1,
                                   .MaximumLength = sizeof(passwordBuffer),
                                   .Buffer = passwordBuffer};

    MSV1_0_INTERACTIVE_LOGON authenticationInformation = {
        // MSV1_0_LOGON_SUBMIT_TYPE value that specifies the type of logon being
        // requested.
        // This member must be set to MsV1_0InteractiveLogon.
        .MessageType = MsV1_0InteractiveLogon,
        .LogonDomainName = domainName,
        .UserName = username,
        .Password = password,
    };

    MSV1_0_INTERACTIVE_PROFILE profileBuffer = {0};
    void *profileBufferVoidPtr = &profileBuffer;

    LUID logonId = {0};
    QUOTA_LIMITS quotas = {0};
    HANDLE lsaLogonUserHandle;
    ULONG profileBufferLen;

    // If the logon failed due to account restrictions, this parameter receives
    // information about why the logon failed. This value is set only if the
    // account information of the user is valid and the logon is rejected.
    NTSTATUS lsaLogonUserSubStatus;

    NTSTATUS logonUserStatus = LsaLogonUser(
        /*[in] HANDLE */ registerLogonProcessHandle,
        /*[in] PLSA_STRING */ &originString,
        /*[in] SECURITY_LOGON_TYPE */ Interactive,
        /*[in] ULONG */ authenticationPackage,
        /*[in] PVOID */ &authenticationInformation,
        /*[in] ULONG */ sizeof(authenticationInformation),
        /*[in, optional] PTOKEN_GROUPS */ NULL,
        /*[in] PTOKEN_SOURCE SourceContext*/ &tokenUserInformation,
        /*[out] PVOID * ProfileBuffer*/ &profileBufferVoidPtr,
        /*[out] PULONG ProfileBufferLength*/ &profileBufferLen,
        /*[out] PLUID LogonId*/ &logonId,
        /*[out] PHANDLE Token*/ &lsaLogonUserHandle,
        /*[out] PQUOTA_LIMITS Quotas*/ &quotas,
        /*[out] PNTSTATUS SubStatus*/ &lsaLogonUserSubStatus);

    printf("logonUserStatus: %ld\n", logonUserStatus);
    logonFailureDebug(logonUserStatus);
    logonFailureDebug(lsaLogonUserSubStatus);

    ULONG ret = LsaNtStatusToWinError(logonUserStatus);
    ret = LsaNtStatusToWinError(lsaLogonUserSubStatus);

    (void)ret;

    return 0;
}
