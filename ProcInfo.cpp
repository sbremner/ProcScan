#define _CRT_SECURE_NO_WARNINGS

#include "ProcInfo.h"
#include "Utils.h"
#include <psapi.h>

DWORD ProcInfo::FindFirst(ProcInfo::PProcessInfo pProcInfo, DWORD dwProcessCount, TCHAR * szName)
{
	for (int k = 0; k < dwProcessCount; k++){
		if (lstrcmp(pProcInfo[k].szExeFile, szName) == 0){
			return k;
		}
	}

	return -1;
}

DWORD ProcInfo::GetPIDByName(ProcInfo::PProcessInfo pProcInfo, DWORD dwProcessCount, TCHAR * name)
{
	for (int k = 0; k < dwProcessCount; k++){
		if (lstrcmp(pProcInfo[k].szExeFile, name) == 0){
			return pProcInfo[k].dwPID;
		}
	}

	return -1;
}

DWORD ProcInfo::GetProcessIndexByPID(ProcInfo::PProcessInfo pProcInfo, DWORD dwProcessCount, DWORD dwPID)
{
	for (int k = 0; k < dwProcessCount; k++){
		if (pProcInfo[k].dwPID == dwPID){
			return k;
		}
	}

	return -1;
}

DWORD ProcInfo::GetCountByName(ProcInfo::PProcessInfo pProcInfo, DWORD dwProcessCount, TCHAR * name)
{
	DWORD count = 0;

	for (int k = 0; k < dwProcessCount; k++){
		if (lstrcmp(pProcInfo[k].szExeFile, name) == 0){
			count++;
		}
	}

	return count;
}

DWORD ProcInfo::GetProcessCount(HANDLE hProcessSnap)
{
	if (hProcessSnap == INVALID_HANDLE_VALUE){
		return 0; // error - can't say that we have any processes
	}

	DWORD count = 0;
	HANDLE hSnapIter = hProcessSnap;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnapIter, &pe32))
	{
		return 0; // error getting process info on first process - we have none!
	}

	do{
		count++; // Process32First is counted on the first iteration;
	} while (Process32Next(hSnapIter, &pe32));

	return count;
}

BOOL ProcInfo::GetProcessInfo(PROCESSENTRY32 pe32, ProcInfo::PProcessInfo pProcInfo)
{
	if (pProcInfo == NULL){
		return FALSE;
	}

	pProcInfo->dwBasePriority = pe32.pcPriClassBase;
	pProcInfo->dwPID = pe32.th32ProcessID;
	pProcInfo->dwParentPID = pe32.th32ParentProcessID;
	strcpy(pProcInfo->szExeFile, pe32.szExeFile);

	if (!ProcessIdToSessionId(pProcInfo->dwPID, &(pProcInfo->dwSessionId)))
	{
		pProcInfo->dwSessionId = -1; // This means that we couldn't get the session id
	}

	return TRUE;
}

// TODO: Add debug token aquiring so that the calls cannot fail when attempting to access them
BOOL ProcInfo::IsValidPath(DWORD dwPID, TCHAR * szPath, TCHAR * szOutPath, DWORD dwOutSize)
{
	HANDLE hProcess = NULL;
	TCHAR filename[MAX_PATH];

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPID);

	if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
		return TRUE; // unable to open path (likely don't have access - need to set Debug Privs)
	}
	
	if (GetModuleFileNameEx(hProcess, NULL, filename, MAX_PATH) == 0) {
		CloseHandle(hProcess);
		return TRUE; // failed here, likely don't have appropriate rights
	}

	CloseHandle(hProcess);

	if (dwOutSize > strlen(filename) && szOutPath != NULL){
		sprintf(szOutPath, "%s", filename); // this will handle the null terminal character for us
	}

	return (lstrcmp(szPath, filename) == 0);
}