/*
	Utility functions
*/

#include "Defines.h"

#ifndef _UTILS_H_
	#define _UTILS_H_

BOOL SetPrivilege(
	DWORD dwPID,			// Process ID to set privs on
	LPCTSTR Privilege,      // Privilege to enable/disable
	BOOL bEnablePrivilege   // TRUE to enable.  FALSE to disable
	);

BOOL SetPrivilege(
	HANDLE hToken,          // token handle
	LPCTSTR Privilege,      // Privilege to enable/disable
	BOOL bEnablePrivilege   // TRUE to enable.  FALSE to disable
	);

BOOL IsInList(TCHAR * str_a, TCHAR ** pszStrings, DWORD dwLength);

BOOL IsAnagram(TCHAR * str_a, TCHAR * str_b);
BOOL IsDuplicateAnagram(TCHAR * str_a, TCHAR * str_b);
DWORD GetMismatchCount(TCHAR * str_a, TCHAR * str_b);

#endif