#include <windows.h>
#include "errhandlingapi.h"
#include "minwindef.h"
#include "securitybaseapi.h"
#include <ntsecapi.h>
#include <stdio.h>
#include <winbase.h>

#define STATUS_SUCCESS 0

// Compile for windows 10 and above
#define _WIN32_WINNT_WIN10 0x0A00
// #define WINVER 0x0A00

DWORD MyLogonUser() {
    printf("calling MyLogonUser with changes LOGON32_LOGON_UNLOCK pass "
           "password\n");

    HANDLE userToken;

    WINBOOL ret = LogonUserA((LPCSTR)"default", NULL,
                             (LPCSTR)"password", LOGON32_LOGON_UNLOCK,
                             LOGON32_PROVIDER_DEFAULT, &userToken);

    printf("LogonUserA ret: %d, Token: %p\n", ret, userToken);

    if (ret == 0) {
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

        printf("LogonUserA: %s\n", messageBuffer);

        // Free the Win32's string's buffer.
        LocalFree(messageBuffer);

        return -1;
    }

    WINBOOL impersonate_return = ImpersonateLoggedOnUser(userToken);

    if (impersonate_return == 0) {
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

        printf("ImpersonateLoggedOnUser: %s\n", messageBuffer);

        // Free the Win32's string's buffer.
        LocalFree(messageBuffer);

        return -1;
    }

    return 0;
}

int main() {
    DWORD ret = MyLogonUser();
    printf("UpdateDefaultPassword ret = %d\n", ret);
    return 0;
}
