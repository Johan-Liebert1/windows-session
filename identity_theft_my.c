#include <stdio.h>
#include <windows.h>

int main() {
    PROCESS_INFORMATION pi = {};
    STARTUPINFOW si = {};

    memset(&si, 0, sizeof(STARTUPINFOW));
    memset(&pi, 0, sizeof(PROCESS_INFORMATION));

    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_SHOW;
    si.lpDesktop = (LPWSTR)L"winsta0\\default"; // Or NULL for default behavior

    // Assuming you have valid handles for input, output, and error. Otherwise,
    // use GetStdHandle to obtain them. si->hStdInput =
    // GetStdHandle(STD_INPUT_HANDLE);   // Standard input si->hStdOutput =
    // GetStdHandle(STD_OUTPUT_HANDLE); // Standard output si->hStdError =
    // GetStdHandle(STD_ERROR_HANDLE);   // Standard error

    WCHAR cmdLine[] = L"explorer.exe";

    BOOL ret = CreateProcessWithLogonW(
        (LPCWSTR)L"defualtuser",  // lpUsername
        NULL,                 // lpDomain, use NULL if local account
        (LPCWSTR)L"password", // lpPassword
        LOGON_WITH_PROFILE,   // dwLogonFlags
        NULL,                 // lpApplicationName
        cmdLine,              // lpCommandLine, writable buffer
        0,   // dwCreationFlags
        NULL,                 // lpEnvironment
        NULL,                 // lpCurrentDirectory
        &si, // lpStartupInfo
        &pi  // lpProcessInformation
    );

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

    printf("CreateProcessAsUser: %s\n", messageBuffer);

    // Free the Win32's string's buffer.
    LocalFree(messageBuffer);

    return 0;
}
