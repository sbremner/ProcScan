/*
	Scanner tool that looks for processes that do not follow the
	common structure of windows.

	By: Steven Bremner
*/

#define _CRT_SECURE_NO_WARNINGS

#include "ProcInfo.h"
#include "ProcRules.h"

#include <tlhelp32.h>
#include <tchar.h>

/*
	Get System root (stdlib.h):
	
	char * pSystemRoot;
	pSystemRoot = getenv ("systemroot");


*/

int main(int argc, char * argv[])
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	DWORD dwProcessCount;
	ProcInfo::PProcessInfo pProcessList;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE){
		printf("Error - unable to get process snapshot.\n");
		return 0;
	}

	// Get count for total processes in our snapshot
	dwProcessCount = ProcInfo::GetProcessCount(hProcessSnap);

	// Allocate room for our processes in our list
	pProcessList = (ProcInfo::PProcessInfo)malloc(sizeof(ProcInfo::ProcessInfo) * dwProcessCount);

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32)){
		printf("Error - unable to enumerate processes.\n");
		return 0;
	}

	for (int i = 0; i < dwProcessCount; i++, Process32Next(hProcessSnap, &pe32))
	{
		if (!ProcInfo::GetProcessInfo(pe32, &pProcessList[i])){
			printf("Error - unable to retreive information for a process.\n");
		}
	}

	RunRules(pProcessList, dwProcessCount);

	CloseHandle(hProcessSnap);
	free(pProcessList);

	return 0;
}