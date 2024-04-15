#include <stdio.h>
#include <windows.h>

#define DESKTOP_ALL                                                            \
    (DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU |         \
     DESKTOP_HOOKCONTROL | DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK |   \
     DESKTOP_ENUMERATE | DESKTOP_WRITEOBJECTS | DESKTOP_SWITCHDESKTOP |        \
     STANDARD_RIGHTS_REQUIRED)

#define WINSTA_ALL                                                             \
    (WINSTA_ENUMDESKTOPS | WINSTA_READATTRIBUTES | WINSTA_ACCESSCLIPBOARD |    \
     WINSTA_CREATEDESKTOP | WINSTA_WRITEATTRIBUTES |                           \
     WINSTA_ACCESSGLOBALATOMS | WINSTA_EXITWINDOWS | WINSTA_ENUMERATE |        \
     WINSTA_READSCREEN | STANDARD_RIGHTS_REQUIRED)

#define GENERIC_ACCESS                                                         \
    (GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL)

BOOL AddAceToWindowStation(HWINSTA hwinsta, PSID psid);

BOOL AddAceToDesktop(HDESK hdesk, PSID psid);

BOOL GetLogonSID(HANDLE hToken, PSID *ppsid);

VOID FreeLogonSID(PSID *ppsid);

VOID FreeLogonSID(PSID *ppsid) {
    HeapFree(GetProcessHeap(), 0, (LPVOID)*ppsid);
}

BOOL GetLogonSID(HANDLE hToken, PSID *ppsid) {
    BOOL bSuccess = FALSE;
    DWORD dwIndex;
    DWORD dwLength = 0;
    PTOKEN_GROUPS ptg = NULL;

    // Verify the parameter passed in is not NULL.
    if (NULL == ppsid)
        goto Cleanup;

    // Get required buffer size and allocate the TOKEN_GROUPS buffer.

    if (!GetTokenInformation(
            hToken,      // handle to the access token
            TokenGroups, // get information about the token's groups
            (LPVOID)ptg, // pointer to TOKEN_GROUPS buffer
            0,           // size of buffer
            &dwLength    // receives required buffer size
            )) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            goto Cleanup;

        ptg = (PTOKEN_GROUPS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                       dwLength);

        if (ptg == NULL)
            goto Cleanup;
    }

    // Get the token group information from the access token.

    if (!GetTokenInformation(
            hToken,      // handle to the access token
            TokenGroups, // get information about the token's groups
            (LPVOID)ptg, // pointer to TOKEN_GROUPS buffer
            dwLength,    // size of buffer
            &dwLength    // receives required buffer size
            )) {
        goto Cleanup;
    }

    // Loop through the groups to find the logon SID.

    for (dwIndex = 0; dwIndex < ptg->GroupCount; dwIndex++)
        if ((ptg->Groups[dwIndex].Attributes & SE_GROUP_LOGON_ID) ==
            SE_GROUP_LOGON_ID) {
            // Found the logon SID; make a copy of it.

            dwLength = GetLengthSid(ptg->Groups[dwIndex].Sid);
            *ppsid =
                (PSID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);

            if (*ppsid == NULL)
                goto Cleanup;

            if (!CopySid(dwLength, *ppsid, ptg->Groups[dwIndex].Sid)) {
                HeapFree(GetProcessHeap(), 0, (LPVOID)*ppsid);
                goto Cleanup;
            }

            break;
        }

    bSuccess = TRUE;

Cleanup:

    // Free the buffer for the token groups.

    if (ptg != NULL)
        HeapFree(GetProcessHeap(), 0, (LPVOID)ptg);

    return bSuccess;
}

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

    printf("%s: %s\n", funcName, messageBuffer);

    // Free the Win32's string's buffer.
    LocalFree(messageBuffer);
}

BOOL SetPrivilege(HANDLE hToken,         // token handle
                  LPCTSTR lpszPrivilege, // name of privilege to enable/disable
                  BOOL bEnablePrivilege  // to enable or disable privilege
) {
    TOKEN_PRIVILEGES tp = {};
    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        PrintLastError("LookupPrivilegeValue");
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

    // Enable or disable the privilege
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES),
                               NULL, NULL)) {
        PrintLastError("AdjustTokenPrivileges");
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("The token does not have the specified privilege. Priv: %s \n",
               lpszPrivilege);
        return FALSE;
    }

    return TRUE;
}

BOOL StartInteractiveClientProcess(
    LPTSTR lpszUsername, // client to log on
    LPTSTR lpszDomain,   // domain of client's account
    LPTSTR lpszPassword, // client's password
    LPWSTR lpCommandLine // command line to execute
) {
    HANDLE hToken;
    HDESK hdesk = NULL;
    HWINSTA hwinsta = NULL, hwinstaSave = NULL;
    PROCESS_INFORMATION pi = {};
    PSID pSid = NULL;
    STARTUPINFOW si = {};
    BOOL bResult = FALSE;

    // Log the client on to the local computer.

    if (!LogonUser(lpszUsername, lpszDomain, lpszPassword,
                   LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
                   &hToken)) {
        printf("Logon user fiailed\n");
        goto Cleanup;
    }

    // Save a handle to the caller's current window station.

    if ((hwinstaSave = GetProcessWindowStation()) == NULL)
        goto Cleanup;

    // Get a handle to the interactive window station.

    hwinsta = OpenWindowStation(
        (LPSTR)("winsta0"),        // the interactive window station
        FALSE,                     // handle is not inheritable
        READ_CONTROL | WRITE_DAC); // rights to read/write the DACL

    if (hwinsta == NULL)
        goto Cleanup;

    // To get the correct default desktop, set the caller's
    // window station to the interactive window station.

    if (!SetProcessWindowStation(hwinsta))
        goto Cleanup;

    // Get a handle to the interactive desktop.

    hdesk = OpenDesktop(
        (LPSTR)("default"), // the interactive window station
        0,                  // no interaction with other desktop processes
        FALSE,              // handle is not inheritable
        READ_CONTROL |      // request the rights to read and write the DACL
            WRITE_DAC | DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS);

    // Restore the caller's window station.

    if (!SetProcessWindowStation(hwinstaSave))
        goto Cleanup;

    if (hdesk == NULL)
        goto Cleanup;

    // Get the SID for the client's logon session.

    if (!GetLogonSID(hToken, &pSid))
        goto Cleanup;

    // Allow logon SID full access to interactive window station.

    if (!AddAceToWindowStation(hwinsta, pSid))
        goto Cleanup;

    // Allow logon SID full access to interactive desktop.

    if (!AddAceToDesktop(hdesk, pSid))
        goto Cleanup;

    // Impersonate client to ensure access to executable file.

    if (!ImpersonateLoggedOnUser(hToken))
        goto Cleanup;

    // Initialize the STARTUPINFO structure.
    // Specify that the process runs in the interactive desktop.

    ZeroMemory(&si, sizeof(STARTUPINFOW));
    si.cb = sizeof(STARTUPINFOW);
    si.lpDesktop = (LPWSTR)L"winsta0\\default";

    if (OpenProcessToken(GetCurrentProcess(),
                         TOKEN_READ | TOKEN_QUERY | TOKEN_DUPLICATE |
                             TOKEN_ASSIGN_PRIMARY,
                         &hToken)) {
        SetPrivilege(hToken, SE_INCREASE_QUOTA_NAME, TRUE);
        SetPrivilege(hToken, SE_TCB_NAME, TRUE);
        SetPrivilege(hToken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);
    } else {
        PrintLastError("OpenProcessToken");
    }

    // Launch the process in the client's logon session.
    printf("Calling CreateProcessAsUserW\n");
    bResult = CreateProcessAsUserW(
        hToken,        // client's access token
        NULL,          // file to execute
        lpCommandLine, // command line
        NULL,          // pointer to process SECURITY_ATTRIBUTES
        NULL,          // pointer to thread SECURITY_ATTRIBUTES
        FALSE,         // handles are not inheritable
        NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE, // creation flags
        NULL, // pointer to new environment block
        NULL, // name of current directory
        &si,  // pointer to STARTUPINFO structure
        &pi   // receives information about new process
    );

    // End impersonation of client.
    RevertToSelf();

    printf("bResult: %p\n", bResult);

    if (bResult && pi.hProcess != INVALID_HANDLE_VALUE) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
    } else {
        PrintLastError("CreateProcessAsUserW");
    }

    // BOOL ret = CreateProcessWithLogonW(
    //     (LPCWSTR)L"Anonymous",      // lpUsername
    //     NULL,                       // lpDomain, use NULL if local account
    //     (LPCWSTR)L"jIEr6TzSy318ri", // lpPassword
    //     LOGON_WITH_PROFILE,         // dwLogonFlags
    //     NULL,                       // lpApplicationName
    //     lpCommandLine,              // lpCommandLine, writable buffer
    //     CREATE_NEW_CONSOLE,         // dwCreationFlags
    //     NULL,                       // lpEnvironment
    //     NULL,                       // lpCurrentDirectory
    //     &si, // lpStartupInfo, assuming 'si' is properly initialized
    //     elsewhere &pi  // lpProcessInformation, assuming 'pi' is declared
    //     elsewhere
    // );

    // if (ret == 0) {
    //     PrintLastError("CreateProcessWithLogonW");
    // }

    if (pi.hThread != INVALID_HANDLE_VALUE)
        CloseHandle(pi.hThread);

Cleanup:
    PrintLastError("Not sure");
    printf("Cleanup: hwinstaSave: %p, psid: %p, hwinsta: %p, hdesk: %p, "
           "hToken: %p",
           hwinstaSave, pSid, hwinsta, hdesk, hToken);

    if (hwinstaSave != NULL)
        SetProcessWindowStation(hwinstaSave);

    // Free the buffer for the logon SID.

    if (pSid)
        FreeLogonSID(&pSid);

    // Close the handles to the interactive window station and desktop.

    if (hwinsta)
        CloseWindowStation(hwinsta);

    if (hdesk)
        CloseDesktop(hdesk);

    // Close the handle to the client's access token.

    if (hToken != INVALID_HANDLE_VALUE)
        CloseHandle(hToken);

    return bResult;
}

BOOL AddAceToWindowStation(HWINSTA hwinsta, PSID psid) {
    ACCESS_ALLOWED_ACE *pace = NULL;
    ACL_SIZE_INFORMATION aclSizeInfo;
    BOOL bDaclExist;
    BOOL bDaclPresent;
    BOOL bSuccess = FALSE;
    DWORD dwNewAclSize;
    DWORD dwSidSize = 0;
    DWORD dwSdSizeNeeded;
    PACL pacl;
    PACL pNewAcl = NULL;
    PSECURITY_DESCRIPTOR psd = NULL;
    PSECURITY_DESCRIPTOR psdNew = NULL;
    PVOID pTempAce;
    SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
    unsigned int i;

    {
        // Obtain the DACL for the window station.

        if (!GetUserObjectSecurity(hwinsta, &si, psd, dwSidSize,
                                   &dwSdSizeNeeded))
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                psd = (PSECURITY_DESCRIPTOR)HeapAlloc(
                    GetProcessHeap(), HEAP_ZERO_MEMORY, dwSdSizeNeeded);

                if (psd == NULL)
                    return 0;

                psdNew = (PSECURITY_DESCRIPTOR)HeapAlloc(
                    GetProcessHeap(), HEAP_ZERO_MEMORY, dwSdSizeNeeded);

                if (psdNew == NULL)
                    return 0;

                dwSidSize = dwSdSizeNeeded;

                if (!GetUserObjectSecurity(hwinsta, &si, psd, dwSidSize,
                                           &dwSdSizeNeeded))
                    return 0;
            } else {
                return 0;
            }

        // Create a new DACL.

        if (!InitializeSecurityDescriptor(psdNew, SECURITY_DESCRIPTOR_REVISION))
            return 0;

        // Get the DACL from the security descriptor.

        if (!GetSecurityDescriptorDacl(psd, &bDaclPresent, &pacl, &bDaclExist))
            return 0;

        // Initialize the ACL.

        ZeroMemory(&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
        aclSizeInfo.AclBytesInUse = sizeof(ACL);

        // Call only if the DACL is not NULL.

        if (pacl != NULL) {
            // get the file ACL size info
            if (!GetAclInformation(pacl, (LPVOID)&aclSizeInfo,
                                   sizeof(ACL_SIZE_INFORMATION),
                                   AclSizeInformation))
                return 0;
        }

        // Compute the size of the new ACL.

        dwNewAclSize = aclSizeInfo.AclBytesInUse +
                       (2 * sizeof(ACCESS_ALLOWED_ACE)) +
                       (2 * GetLengthSid(psid)) - (2 * sizeof(DWORD));

        // Allocate memory for the new ACL.

        pNewAcl =
            (PACL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwNewAclSize);

        if (pNewAcl == NULL)
            return 0;

        // Initialize the new DACL.

        if (!InitializeAcl(pNewAcl, dwNewAclSize, ACL_REVISION))
            return 0;

        // If DACL is present, copy it to a new DACL.

        if (bDaclPresent) {
            // Copy the ACEs to the new ACL.
            if (aclSizeInfo.AceCount) {
                for (i = 0; i < aclSizeInfo.AceCount; i++) {
                    // Get an ACE.
                    if (!GetAce(pacl, i, &pTempAce))
                        return 0;

                    // Add the ACE to the new ACL.
                    if (!AddAce(pNewAcl, ACL_REVISION, MAXDWORD, pTempAce,
                                ((PACE_HEADER)pTempAce)->AceSize))
                        return 0;
                }
            }
        }

        // Add the first ACE to the window station.

        pace = (ACCESS_ALLOWED_ACE *)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY,
            sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) - sizeof(DWORD));

        if (pace == NULL)
            return 0;

        pace->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
        pace->Header.AceFlags =
            CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE;
        pace->Header.AceSize = LOWORD(sizeof(ACCESS_ALLOWED_ACE) +
                                      GetLengthSid(psid) - sizeof(DWORD));
        pace->Mask = GENERIC_ACCESS;

        if (!CopySid(GetLengthSid(psid), &pace->SidStart, psid))
            return 0;

        if (!AddAce(pNewAcl, ACL_REVISION, MAXDWORD, (LPVOID)pace,
                    pace->Header.AceSize))
            return 0;

        // Add the second ACE to the window station.

        pace->Header.AceFlags = NO_PROPAGATE_INHERIT_ACE;
        pace->Mask = WINSTA_ALL;

        if (!AddAce(pNewAcl, ACL_REVISION, MAXDWORD, (LPVOID)pace,
                    pace->Header.AceSize))
            return 0;

        // Set a new DACL for the security descriptor.

        if (!SetSecurityDescriptorDacl(psdNew, TRUE, pNewAcl, FALSE))
            return 0;

        // Set the new security descriptor for the window station.

        if (!SetUserObjectSecurity(hwinsta, &si, psdNew))
            return 0;

        // Indicate success.

        bSuccess = TRUE;
    }
    {
        // Free the allocated buffers.

        if (pace != NULL)
            HeapFree(GetProcessHeap(), 0, (LPVOID)pace);

        if (pNewAcl != NULL)
            HeapFree(GetProcessHeap(), 0, (LPVOID)pNewAcl);

        if (psd != NULL)
            HeapFree(GetProcessHeap(), 0, (LPVOID)psd);

        if (psdNew != NULL)
            HeapFree(GetProcessHeap(), 0, (LPVOID)psdNew);
    }

    return bSuccess;
}

BOOL AddAceToDesktop(HDESK hdesk, PSID psid) {
    ACL_SIZE_INFORMATION aclSizeInfo;
    BOOL bDaclExist;
    BOOL bDaclPresent;
    BOOL bSuccess = FALSE;
    DWORD dwNewAclSize;
    DWORD dwSidSize = 0;
    DWORD dwSdSizeNeeded;
    PACL pacl;
    PACL pNewAcl = NULL;
    PSECURITY_DESCRIPTOR psd = NULL;
    PSECURITY_DESCRIPTOR psdNew = NULL;
    PVOID pTempAce;
    SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
    unsigned int i;

    {
        // Obtain the security descriptor for the desktop object.

        if (!GetUserObjectSecurity(hdesk, &si, psd, dwSidSize,
                                   &dwSdSizeNeeded)) {
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                psd = (PSECURITY_DESCRIPTOR)HeapAlloc(
                    GetProcessHeap(), HEAP_ZERO_MEMORY, dwSdSizeNeeded);

                if (psd == NULL)
                    return 0;

                psdNew = (PSECURITY_DESCRIPTOR)HeapAlloc(
                    GetProcessHeap(), HEAP_ZERO_MEMORY, dwSdSizeNeeded);

                if (psdNew == NULL)
                    return 0;

                dwSidSize = dwSdSizeNeeded;

                if (!GetUserObjectSecurity(hdesk, &si, psd, dwSidSize,
                                           &dwSdSizeNeeded))
                    return 0;
            } else {
                return 0;
            }
        }

        // Create a new security descriptor.

        if (!InitializeSecurityDescriptor(psdNew, SECURITY_DESCRIPTOR_REVISION))
            return 0;

        // Obtain the DACL from the security descriptor.

        if (!GetSecurityDescriptorDacl(psd, &bDaclPresent, &pacl, &bDaclExist))
            return 0;

        // Initialize.

        ZeroMemory(&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
        aclSizeInfo.AclBytesInUse = sizeof(ACL);

        // Call only if NULL DACL.

        if (pacl != NULL) {
            // Determine the size of the ACL information.

            if (!GetAclInformation(pacl, (LPVOID)&aclSizeInfo,
                                   sizeof(ACL_SIZE_INFORMATION),
                                   AclSizeInformation))
                return 0;
        }

        // Compute the size of the new ACL.

        dwNewAclSize = aclSizeInfo.AclBytesInUse + sizeof(ACCESS_ALLOWED_ACE) +
                       GetLengthSid(psid) - sizeof(DWORD);

        // Allocate buffer for the new ACL.

        pNewAcl =
            (PACL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwNewAclSize);

        if (pNewAcl == NULL)
            return 0;

        // Initialize the new ACL.

        if (!InitializeAcl(pNewAcl, dwNewAclSize, ACL_REVISION))
            return 0;

        // If DACL is present, copy it to a new DACL.

        if (bDaclPresent) {
            // Copy the ACEs to the new ACL.
            if (aclSizeInfo.AceCount) {
                for (i = 0; i < aclSizeInfo.AceCount; i++) {
                    // Get an ACE.
                    if (!GetAce(pacl, i, &pTempAce))
                        return 0;

                    // Add the ACE to the new ACL.
                    if (!AddAce(pNewAcl, ACL_REVISION, MAXDWORD, pTempAce,
                                ((PACE_HEADER)pTempAce)->AceSize))
                        return 0;
                }
            }
        }

        // Add ACE to the DACL.

        if (!AddAccessAllowedAce(pNewAcl, ACL_REVISION, DESKTOP_ALL, psid))
            return 0;

        // Set new DACL to the new security descriptor.

        if (!SetSecurityDescriptorDacl(psdNew, TRUE, pNewAcl, FALSE))
            return 0;

        // Set the new security descriptor for the desktop object.

        if (!SetUserObjectSecurity(hdesk, &si, psdNew))
            return 0;

        // Indicate success.

        bSuccess = TRUE;
    }
    {
        // Free buffers.

        if (pNewAcl != NULL)
            HeapFree(GetProcessHeap(), 0, (LPVOID)pNewAcl);

        if (psd != NULL)
            HeapFree(GetProcessHeap(), 0, (LPVOID)psd);

        if (psdNew != NULL)
            HeapFree(GetProcessHeap(), 0, (LPVOID)psdNew);
    }

    return bSuccess;
}

int main() {
    WCHAR cmdLine[] = L"\"C:\\Program Files\\NI\\yaoe_win.exe\" serve";
    // WCHAR cmdLine[] = L"\"powershell\" -File C:\\exe.ps1";

    StartInteractiveClientProcess((LPSTR) "defaultuser", NULL,
                                  (LPSTR) "password", cmdLine);

    return 0;
}
