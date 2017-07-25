/*
	Applies the rules (these are hardcoded for now but should be
	turned into something modular later on)
*/

#include "ProcInfo.h"

#define RULE_FUNCTION(NAME) BOOL WINAPI NAME ## _rule(ProcInfo::PProcessInfo pProcInfo, DWORD dwProcessCount)
#define RULE(NAME) (zProcessRule)(NAME ## _rule)

#define LOG_RULE(NAME, MSG, ...) printf("[" #NAME "] :: " MSG "\n", __VA_ARGS__ )

#define INVALID_SESSION_ID -1
#define SYSTEM_PID 4

#define SYSTEMROOT ( getenv("systemroot") )

#define SYSTEMROOT_FILE(FILENAME, szSTRING) ( sprintf(szSTRING, "%s\\%s", SYSTEMROOT, FILENAME) )
#define SYSTEM32_FILE(FILENAME, szSTRING) ( sprintf(szSTRING, "%s\\System32\\%s", SYSTEMROOT, FILENAME) )

void RunRules(ProcInfo::PProcessInfo pProcessInfo, DWORD dwProcessCount);
BOOL IsProcessStandard(ProcInfo::PProcessInfo ProcInfo, DWORD dwProcessCount, DWORD dwProcessIndex);

//typedef BOOL(WINAPI *zProcessRule)	(PProcessInfo pProcInfo, DWORD dwProcessCount, DWORD dwProcessIndex);
typedef BOOL(WINAPI *zProcessRule) (ProcInfo::PProcessInfo pProcInfo, DWORD dwProcessCount);
