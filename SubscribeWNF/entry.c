#include <windows.h>
#include "typedefs.h"
#include "beacon.h"

#define HashStringNtdll 0x467f5122
#define HashStringRtlSubscribeWnfStateChangeNotification 0x2098e735
#define HashStringRtlUnsubscribeWnfStateChangeNotification 0x83d07400

#define HashStringA(x) HashStringFowlerNollVoVariant1aA(x)
#define HashStringW(x) HashStringFowlerNollVoVariant1aW(x)

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReleaseMutex(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateMutexA(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
DECLSPEC_IMPORT VOID WINAPI KERNEL32$Sleep(DWORD);

DWORDLONG WNF_SHEL_APPLICATION_STARTED = 0x0d83063ea3be0075;
//DWORDLONG WNF_SHEL_DESKTOP_APPLICATION_STARTED = 0x0d83063ea3be5075;
DWORDLONG WNF_SHEL_APPLICATION_TERMINATED = 0x0d83063ea3be0875;
//DWORDLONG WNF_SHEL_DESKTOP_APPLICATION_TERMINATED = 0x0d83063ea3be5875;

HANDLE _callbackMutex __attribute__ ((section(".data")));

ULONG HashStringFowlerNollVoVariant1aA(_In_ LPCSTR String) {
    ULONG Hash = 0x6A6CCC06;

    while (*String) {
        Hash ^= (UCHAR)*String++;
        Hash *= 0x25EDE3FB;
    }

    return Hash;
}

ULONG HashStringFowlerNollVoVariant1aW(_In_ LPCWSTR String) {
    ULONG Hash = 0x6A6CCC06;

    while (*String) {
        Hash ^= (UCHAR)*String++;
        Hash *= 0x25EDE3FB;
    }

    return Hash;
}

HMODULE _GetModuleHandle(_In_ ULONG dllHash) {
    PLIST_ENTRY head = (PLIST_ENTRY) & ((PPEB)__readgsqword(0x60))->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY next = head->Flink;

    PLDR_MODULE module = (PLDR_MODULE)((PBYTE)next - 16);

    while (next != head) {
        module = (PLDR_MODULE)((PBYTE)next - 16);
        if (module->BaseDllName.Buffer != NULL) {
            if (dllHash - HashStringW(module->BaseDllName.Buffer) == 0)
                return (HMODULE)module->BaseAddress;
        }
        next = next->Flink;
    }

    return NULL;
}

// Stolen from: https://github.com/iilegacyyii/ThreadlessInject-BOF/blob/fad40ed164e83504ef0c1e5180990a9bb147d8d2/entry.c#L62
FARPROC _GetProcAddress(_In_ HMODULE dllBase, _In_ ULONG funcHash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)(dllBase);
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)dos + (dos)->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = 
        (PIMAGE_EXPORT_DIRECTORY)((PBYTE)dos + (nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    if (exports->AddressOfNames != 0) {
        PWORD ordinals = (PWORD)((UINT_PTR)dllBase + exports->AddressOfNameOrdinals);
        PDWORD names = (PDWORD)((UINT_PTR)dllBase + exports->AddressOfNames);
        PDWORD functions = (PDWORD)((UINT_PTR)dllBase + exports->AddressOfFunctions);

        for (DWORD i = 0; i < exports->NumberOfNames; i++) {
            LPCSTR name = (LPCSTR)((UINT_PTR)dllBase + names[i]);
            if (HashStringA(name) == funcHash) {
                PBYTE function = (PBYTE)((UINT_PTR)dllBase + functions[ordinals[i]]);
                return (FARPROC)function;
            }
        }
    }

    return NULL;
}

NTSTATUS NTAPI WnfCallback(DWORDLONG p1, PVOID p2, PVOID p3, PVOID p4, PVOID p5, PVOID p6) {
    KERNEL32$WaitForSingleObject(_callbackMutex, INFINITE);

    LPCWSTR stateName;
    if (p1 == WNF_SHEL_APPLICATION_STARTED)
        stateName = L"APPLICATION_STARTED";
    //else if (p1 == WNF_SHEL_DESKTOP_APPLICATION_STARTED)
    //    stateName = L"DESKTOP_APPLICATION_STARTED";
    else if (p1 == WNF_SHEL_APPLICATION_TERMINATED)
        stateName = L"APPLICATION_TERMINATED";
    //else if (p1 == WNF_SHEL_DESKTOP_APPLICATION_TERMINATED)
    //    stateName = L"DESKTOP_APPLICATION_TERMINATED";
    else
        stateName = L"UNKNOWN";

    BeaconPrintf(CALLBACK_OUTPUT, "%ls --> %ls\n", stateName, (LPCWSTR)p5);

    KERNEL32$ReleaseMutex(_callbackMutex);

    return 0;
}

PVOID subscribe(DWORDLONG stateName) {
    PVOID* subscription;
    DWORD changeStamp;

    HMODULE ntdllBase = _GetModuleHandle(HashStringNtdll);

    typeRtlSubscribeWnfStateChangeNotification pRtlSubscribeWnfStateChangeNotification =
        (typeRtlSubscribeWnfStateChangeNotification)_GetProcAddress(
            ntdllBase,
            HashStringRtlSubscribeWnfStateChangeNotification);

    NTSTATUS ntstatus = pRtlSubscribeWnfStateChangeNotification(
        &subscription,
        stateName,
        changeStamp,
        WnfCallback,
        0,
        0,
        0,
        1);

    if (ntstatus != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "Subscription %llx failed: %08x\n", stateName, ntstatus);
        return NULL;
    }

    return subscription;
}

NTSTATUS unsubscribe(PVOID subscription, DWORDLONG stateName) {
    HMODULE ntdllBase = _GetModuleHandle(HashStringNtdll);

    typeRtlUnsubscribeWnfStateChangeNotification pRtlUnsubscribeWnfStateChangeNotification = 
        (typeRtlUnsubscribeWnfStateChangeNotification)_GetProcAddress(
            ntdllBase,
            HashStringRtlUnsubscribeWnfStateChangeNotification);

    NTSTATUS ntstatus = pRtlUnsubscribeWnfStateChangeNotification(subscription);

    if (ntstatus != 0)
        BeaconPrintf(CALLBACK_OUTPUT, "Unsubscription %llx failed: %08x\n", stateName, ntstatus);

    return ntstatus;
}

void go(char* args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);
    SIZE_T seconds = BeaconDataInt(&parser);

    _callbackMutex = KERNEL32$CreateMutexA(NULL, FALSE, NULL);
    if (!_callbackMutex)
        return;

    KERNEL32$WaitForSingleObject(_callbackMutex, INFINITE);

    PVOID subscription1, subscription2, subscription3, subscription4;
    if ((subscription1 = subscribe(WNF_SHEL_APPLICATION_STARTED)) == NULL)
        return;
    //if ((subscription2 = subscribe(WNF_SHEL_DESKTOP_APPLICATION_STARTED)) == NULL) {
    //    unsubscribe(subscription1, WNF_SHEL_APPLICATION_STARTED);
    //    return;
    //}
    if ((subscription3 = subscribe(WNF_SHEL_APPLICATION_TERMINATED)) == NULL) {
        //unsubscribe(subscription2, WNF_SHEL_DESKTOP_APPLICATION_STARTED);
        unsubscribe(subscription1, WNF_SHEL_APPLICATION_STARTED);
        return;
    }
    //if ((subscription4 = subscribe(WNF_SHEL_DESKTOP_APPLICATION_TERMINATED)) == NULL) {
    //    unsubscribe(subscription3, WNF_SHEL_APPLICATION_TERMINATED);
    //    unsubscribe(subscription2, WNF_SHEL_DESKTOP_APPLICATION_STARTED);
    //    unsubscribe(subscription1, WNF_SHEL_APPLICATION_STARTED);
    //    return;
    //}

    KERNEL32$ReleaseMutex(_callbackMutex);

    KERNEL32$Sleep((DWORD)seconds * 1000);

    //unsubscribe(subscription4, WNF_SHEL_DESKTOP_APPLICATION_TERMINATED);
    unsubscribe(subscription3, WNF_SHEL_APPLICATION_TERMINATED);
    //unsubscribe(subscription2, WNF_SHEL_DESKTOP_APPLICATION_STARTED);
    unsubscribe(subscription1, WNF_SHEL_APPLICATION_STARTED);
    
    return;
}
