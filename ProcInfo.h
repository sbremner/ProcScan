/*
	Structures and functions to assist in retrieving process information
*/

#ifndef _PROCINFO_H_
	#define _PROCINFO_H_

#include "Defines.h"

#include <tlhelp32.h>

namespace ProcInfo {

	typedef struct ProccessInfo{
		DWORD dwPID;
		DWORD dwParentPID;
		DWORD dwSessionId;
		DWORD dwBasePriority;
		TCHAR szExeFile[MAX_PATH];

	} ProcessInfo, *PProcessInfo;

	DWORD FindFirst(PProcessInfo pProcInfo, DWORD dwProcessCount, TCHAR * name);

	DWORD GetPIDByName(PProcessInfo pProcInfo, DWORD dwProcessCount, TCHAR * name);
	DWORD GetProcessIndexByPID(PProcessInfo pProcInfo, DWORD dwProcessCount, DWORD dwPID);
	DWORD GetCountByName(PProcessInfo pProcInfo, DWORD dwProcessCount, TCHAR * name);
	DWORD GetProcessCount(HANDLE hProcessSnap);
	BOOL GetProcessInfo(PROCESSENTRY32 pe32, PProcessInfo pProcInfo);

	BOOL IsValidPath(DWORD dwPID, TCHAR * szPath, TCHAR * szOutPath, DWORD dwOutSize);
};

#endif