#include "Utils.h"

#include <string>
#include <algorithm>

BOOL SetPrivilege(DWORD dwPID, LPCTSTR Privilege, BOOL bEnablePrivilege)
{
	HANDLE hToken = INVALID_HANDLE_VALUE;
	BOOL bRet = TRUE;

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPID);


	if (hProcess != NULL){
		if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		{
			if (GetLastError() == ERROR_NO_TOKEN)
			{
				if (!ImpersonateSelf(SecurityImpersonation))
				{
					bRet = FALSE;
				}

				if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)){
					bRet = FALSE;
				}
			}
			else
			{
				bRet = FALSE;
			}
		}
	}
	else{
		bRet = FALSE;
	}

	if (bRet == TRUE){
		bRet = SetPrivilege(hToken, Privilege, bEnablePrivilege);
	}

	if (hToken != NULL && hToken != INVALID_HANDLE_VALUE){
		CloseHandle(hToken);
	}

	if (hProcess != NULL && hProcess != INVALID_HANDLE_VALUE){
		CloseHandle(hProcess);
	}

	return bRet;
}

BOOL SetPrivilege(
	HANDLE hToken,          // token handle
	LPCTSTR Privilege,      // Privilege to enable/disable
	BOOL bEnablePrivilege   // TRUE to enable.  FALSE to disable
	)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	if (!LookupPrivilegeValue(NULL, Privilege, &luid)) return FALSE;

	// 
	// first pass.  get current privilege setting
	// 
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = 0;

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		&tpPrevious,
		&cbPrevious
		);

	if (GetLastError() != ERROR_SUCCESS) return FALSE;

	// 
	// second pass.  set privilege based on previous setting
	// 
	tpPrevious.PrivilegeCount = 1;
	tpPrevious.Privileges[0].Luid = luid;

	if (bEnablePrivilege) {
		tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
	}
	else {
		tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &
			tpPrevious.Privileges[0].Attributes);
	}

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tpPrevious,
		cbPrevious,
		NULL,
		NULL
		);

	if (GetLastError() != ERROR_SUCCESS) return FALSE;

	return TRUE;
};

BOOL IsInList(TCHAR * str_a, TCHAR ** pszStrings, DWORD dwLength)
{
	for (int k = 0; k < dwLength; k++){
		if (ISMATCH(str_a, pszStrings[k])){
			return TRUE;
		}
	}

	return FALSE;
}

BOOL IsAnagram(TCHAR * str_a, TCHAR * str_b)
{
	if (str_a == NULL || str_b == NULL){
		return FALSE;
	}

	if (strlen(str_a) != strlen(str_b)){
		return FALSE;
	}

	std::string string_a(str_a);
	std::string string_b(str_b);

	std::sort(string_a.begin(), string_a.end());
	std::sort(string_b.begin(), string_b.end());

	// We are the same length here (we checked above)
	for (int k = 0; k < string_a.length(); k++){
		if (tolower(string_a[k]) != tolower(string_b[k])){
			return FALSE;
		}
	}

	return TRUE; // if we made it here, we didnt fail any checks
}

BOOL IsDuplicateAnagram(TCHAR * str_a, TCHAR * str_b)
{
	if (str_a == NULL || str_b == NULL){
		return FALSE;
	}

	std::string string_a(str_a);
	std::string string_b(str_b);

	std::sort(string_a.begin(), string_a.end());
	std::sort(string_b.begin(), string_b.end());

	CONST TCHAR * c_str_A = string_a.c_str();
	CONST TCHAR * c_str_B = string_b.c_str();

	char previous = NULL;

	for (int a = 0, b = 0; a < strlen(c_str_A) && b < strlen(c_str_B);)
	{
		// If they are both the same, we iterate both
		if (tolower(c_str_A[a]) == tolower(c_str_B[b])){
			previous = tolower(c_str_A[a]);
			a++;
			b++;
		}
		// string A has a repeated character (just skip A - don't update previous)
		else if (tolower(c_str_A[a]) == previous){
			a++;
		}
		// string B has a repeated character (just skip B - don't update previous)
		else if (tolower(c_str_B[b] == previous)){
			b++;
		}
		// In this else case, there is a very clear different between the strings (not just duplicate characters)
		else {
			return FALSE;
		}
	}

	return TRUE; // if we made it here, we didnt fail any checks
}

DWORD GetMismatchCount(TCHAR * str_a, TCHAR * str_b)
{
	DWORD dwLength = min(strlen(str_a), strlen(str_b));
	DWORD dwMismatchCount = 0;

	for (int k = 0; k < dwLength; k++){
		if (tolower(str_a[k]) != tolower(str_b[k])){
			dwMismatchCount++; // we have a mismatch!
		}
	}

	return dwMismatchCount;
}