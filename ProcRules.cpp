#define _CRT_SECURE_NO_WARNINGS

#include "ProcRules.h"
#include "Utils.h"

#include <WtsApi32.h>

RULE_FUNCTION(system){
	BOOL bRet = TRUE; // Starts true, failures make this false
	DWORD dwCount = GetCountByName(pProcInfo, dwProcessCount, "System");

	if (dwCount != 1){
		LOG_RULE(system, "System process should exist one time (Count = %d)", dwCount);
		bRet = FALSE;
	}

	for (unsigned int k = 0; k < dwProcessCount; k++, bRet = TRUE){
		if (lstrcmp("System", pProcInfo[k].szExeFile) == 0){
			ProcInfo::ProcessInfo process = pProcInfo[k];

			LOG_RULE(system, "Starting rules for system (PID = %d)", process.dwPID);

			/* START RULE CHECKS */
			if (process.dwPID != SYSTEM_PID){
				LOG_RULE(system, "System pid is not 4 (PID = %d)", process.dwPID);
				bRet = FALSE;
			}

			if (process.dwSessionId != 0 && process.dwSessionId != INVALID_SESSION_ID){
				LOG_RULE(system, "System process should have SessionId 0 (SessionId = %d)", process.dwSessionId);
				bRet = FALSE;
			}
			/* END RULE CHECKS */

			LOG_RULE(system, "Status = %s (PID = %d)\n", bRet ? "PASSED" : "FAILED", process.dwPID);
		}
	}

	return bRet;
}

RULE_FUNCTION(smss){
	BOOL bRet = TRUE; // Starts true, failures make this false
	DWORD dwCount = GetCountByName(pProcInfo, dwProcessCount, "smss.exe");

	char szOutPath[MAX_PATH];

	if (dwCount != 1){
		LOG_RULE(smss, "smss.exe process should exist one time (Count = %d)", dwCount);
		bRet = FALSE;
	}

	for (unsigned int k = 0; k < dwProcessCount; k++, bRet = TRUE){
		if (lstrcmp("smss.exe", pProcInfo[k].szExeFile) == 0){
			ProcInfo::ProcessInfo process = pProcInfo[k];

			LOG_RULE(smss, "Starting rules for smss.exe (PID = %d)", process.dwPID);

			/* START RULE CHECKS */
			char szFilepath[MAX_PATH];
			SYSTEM32_FILE("smss.exe", szFilepath); // build our file path

			if (!ProcInfo::IsValidPath(process.dwPID, szFilepath, szOutPath, MAX_PATH)){
				LOG_RULE(smss, "File is not located at: %s (Location = %s)", szFilepath, szOutPath);
				bRet = FALSE;
			}

			if (process.dwParentPID != SYSTEM_PID) {
				LOG_RULE(smss, "smss.exe should have System as its Parent PID (Parent PID = %d)", process.dwParentPID);
				bRet = FALSE;
			}

			if (process.dwSessionId != 0 && process.dwSessionId != INVALID_SESSION_ID){
				LOG_RULE(smss, "smss.exe should have SessionId 0 (SessionId = %d)", process.dwSessionId);
				bRet = FALSE;
			}

			if (process.dwBasePriority != 11) {
				LOG_RULE(smss, "smss.exe should have a base priority of 11 (Base Priority = %d)", process.dwBasePriority);
				bRet = FALSE;
			}
			/* END RULE CHECKS */

			LOG_RULE(smss, "Status = %s (PID = %d)\n", bRet ? "PASSED" : "FAILED", process.dwPID);
		}
	}

	return bRet;
}

RULE_FUNCTION(csrss){
	BOOL bRet = TRUE; // Starts true, failures make this false
	
	char szOutPath[MAX_PATH];

	DWORD dwCount = GetCountByName(pProcInfo, dwProcessCount, "csrss.exe");
	HANDLE hServer = WTSOpenServerA("127.0.0.1");

	if (hServer != NULL){
		PWTS_SESSION_INFO pSessionInfo;
		DWORD dwSessionCount = 0, dwActiveSessionCount = 0;

		if (WTSEnumerateSessions(hServer, 0, 1, &pSessionInfo, &dwSessionCount)){
			for (int k = 0; k < dwSessionCount; k++){
				if (pSessionInfo[k].State != WTS_CONNECTSTATE_CLASS::WTSDisconnected && pSessionInfo[k].State != WTS_CONNECTSTATE_CLASS::WTSDown){
					dwActiveSessionCount++;
				}
			}

			if (dwCount != dwActiveSessionCount){
				LOG_RULE(csrss, "csrss.exe should exist one time per active session (Count = %d, Sessions = %d)", dwCount, dwSessionCount);
				for (int k = 0; k < dwSessionCount; k++){
					if (pSessionInfo[k].State != WTS_CONNECTSTATE_CLASS::WTSDisconnected && pSessionInfo[k].State != WTS_CONNECTSTATE_CLASS::WTSDown) {
						LOG_RULE(csrss, "Session: %s | Session Id: %d (State = %d)", pSessionInfo[k].pWinStationName, pSessionInfo[k].SessionId, pSessionInfo[k].State);
					}
				}
				bRet = FALSE;
			}
		}
		CloseHandle(hServer);
	}

	for (unsigned int k = 0; k < dwProcessCount; k++, bRet = TRUE){
		if (lstrcmp("csrss.exe", pProcInfo[k].szExeFile) == 0){
			ProcInfo::ProcessInfo process = pProcInfo[k];

			LOG_RULE(csrss, "Starting rules for csrss.exe (PID = %d)", process.dwPID);

			/* START RULE CHECKS */

			char szFilepath[MAX_PATH];
			SYSTEM32_FILE("csrss.exe", szFilepath); // build our file path

			if (!ProcInfo::IsValidPath(process.dwPID, szFilepath, szOutPath, MAX_PATH)){
				LOG_RULE(csrss, "File is not located at: %s (Location = %s)", szFilepath, szOutPath);
				bRet = FALSE;
			}

			if (process.dwSessionId != 1 && process.dwSessionId != INVALID_SESSION_ID){
				LOG_RULE(csrss, "csrss.exe should have SessionId 1 (SessionId = %d)", process.dwSessionId);
				bRet = FALSE;
			}

			if (process.dwBasePriority != 13){
				LOG_RULE(smss, "csrss.exe should have a base priority of 13 (Base Priority = %d)", process.dwBasePriority);
				bRet = FALSE;
			}
			/* END RULE CHECKS */
			
			LOG_RULE(csrss, "Status = %s (PID = %d)\n", bRet ? "PASSED" : "FAILED", process.dwPID);
		}
	}

	return bRet;
}

RULE_FUNCTION(wininit){
	BOOL bRet = TRUE; // Starts true, failures make this false
	char szOutPath[MAX_PATH];
	
	DWORD dwCount = GetCountByName(pProcInfo, dwProcessCount, "wininit.exe");

	if (dwCount != 1){
		LOG_RULE(wininit, "wininit.exe should exist one time (Count = %d)", dwCount);
	}

	for (unsigned int k = 0; k < dwProcessCount; k++, bRet = TRUE){
		if (lstrcmp("wininit.exe", pProcInfo[k].szExeFile) == 0){
			ProcInfo::ProcessInfo process = pProcInfo[k];

			LOG_RULE(wininit, "Starting rules for wininit.exe (PID = %d)", process.dwPID);

			/* START RULE CHECKS */
			char szFilepath[MAX_PATH];
			SYSTEM32_FILE("wininit.exe", szFilepath); // build our file path

			if (!ProcInfo::IsValidPath(process.dwPID, szFilepath, szOutPath, MAX_PATH)){
				LOG_RULE(wininit, "File is not located at: %s (Location = %s)", szFilepath, szOutPath);
				bRet = FALSE;
			}

			if (process.dwSessionId != 0 && process.dwSessionId != INVALID_SESSION_ID){
				LOG_RULE(wininit, "wininit.exe should have SessionId 0 (SessionId = %d)", process.dwSessionId);
				bRet = FALSE;
			}

			if (process.dwBasePriority != 13){
				LOG_RULE(wininit, "wininit.exe should have a base priority of 13 (Base Priority = %d)", process.dwBasePriority);
				bRet = FALSE;
			}
			/* END RULE CHECKS */

			LOG_RULE(wininit, "Status = %s (PID = %d)\n", bRet ? "PASSED" : "FAILED", process.dwPID);
		}
	}

	return bRet;
}

RULE_FUNCTION(services){
	BOOL bRet = TRUE; // Starts true, failures make this false
	char szOutPath[MAX_PATH];

	DWORD dwCount = GetCountByName(pProcInfo, dwProcessCount, "services.exe");

	if (dwCount != 1){
		LOG_RULE(services, "services.exe should exist one time (Count = %d)", dwCount);
	}

	for (unsigned int k = 0; k < dwProcessCount; k++, bRet = TRUE){
		if (lstrcmp("services.exe", pProcInfo[k].szExeFile) == 0){
			ProcInfo::ProcessInfo process = pProcInfo[k];

			LOG_RULE(services, "Starting rules for services.exe (PID = %d)", process.dwPID);

			/* START RULE CHECKS */
			char szFilepath[MAX_PATH];
			SYSTEM32_FILE("services.exe", szFilepath); // build our file path

			if (!ProcInfo::IsValidPath(process.dwPID, szFilepath, szOutPath, MAX_PATH)){
				LOG_RULE(services, "File is not located at: %s (Location = %s)", szFilepath, szOutPath);
				bRet = FALSE;
			}

			if (process.dwSessionId != 0 && process.dwSessionId != INVALID_SESSION_ID){
				LOG_RULE(services, "services.exe should have SessionId 0 (SessionId = %d)", process.dwSessionId);
				bRet = FALSE;
			}

			if (process.dwBasePriority != 9){
				LOG_RULE(services, "services.exe should have a base priority of 9 (Base Priority = %d)", process.dwBasePriority);
				bRet = FALSE;
			}
			/* END RULE CHECKS */

			LOG_RULE(services, "Status = %s (PID = %d)\n", bRet ? "PASSED" : "FAILED", process.dwPID);
		}
	}

	return bRet;
}

RULE_FUNCTION(lsass){
	BOOL bRet = TRUE; // Starts true, failures make this false
	char szOutPath[MAX_PATH];

	DWORD dwCount = GetCountByName(pProcInfo, dwProcessCount, "lsass.exe");

	if (dwCount != 1){
		LOG_RULE(lsass, "lsass.exe should exist one time (Count = %d)", dwCount);
	}

	for (unsigned int k = 0; k < dwProcessCount; k++, bRet = TRUE){
		if (lstrcmp("lsass.exe", pProcInfo[k].szExeFile) == 0){
			ProcInfo::ProcessInfo process = pProcInfo[k];

			LOG_RULE(lsass, "Starting rules for lsass.exe (PID = %d)", process.dwPID);

			/* START RULE CHECKS */
			char szFilepath[MAX_PATH];
			SYSTEM32_FILE("lsass.exe", szFilepath); // build our file path

			if (!ProcInfo::IsValidPath(process.dwPID, szFilepath, szOutPath, MAX_PATH)){
				LOG_RULE(lsass, "File is not located at: %s (Location = %s)", szFilepath, szOutPath);
				bRet = FALSE;
			}

			if (process.dwSessionId != 0 && process.dwSessionId != INVALID_SESSION_ID){
				LOG_RULE(lsass, "lsass.exe should have SessionId 0 (SessionId = %d)", process.dwSessionId);
				bRet = FALSE;
			}

			if (process.dwBasePriority != 9){
				LOG_RULE(lsass, "lsass.exe should have a base priority of 9 (Base Priority = %d)", process.dwBasePriority);
				bRet = FALSE;
			}
			/* END RULE CHECKS */

			LOG_RULE(lsass, "Status = %s (PID = %d)\n", bRet ? "PASSED" : "FAILED", process.dwPID);
		}
	}

	return bRet;
}

RULE_FUNCTION(svchost){
	BOOL bRet = TRUE; // Starts true, failures make this false
	char szOutPath[MAX_PATH];

	// Run the rules for all of our svchost processes
	for (unsigned int k = 0; k < dwProcessCount; k++, bRet = TRUE){
		if (lstrcmp("svchost.exe", pProcInfo[k].szExeFile) == 0){
			ProcInfo::ProcessInfo process = pProcInfo[k];

			LOG_RULE(svchost, "Starting rules for svchost.exe (PID = %d)", process.dwPID);

			/* START RULE CHECKS */
			char szFilepath[MAX_PATH];
			SYSTEM32_FILE("svchost.exe", szFilepath); // build our file path

			if (!ProcInfo::IsValidPath(process.dwPID, szFilepath, szOutPath, MAX_PATH)){
				LOG_RULE(svchost, "File is not located at: %s (Location = %s)", szFilepath, szOutPath);
				bRet = FALSE;
			}

			DWORD dwParentIndex = GetProcessIndexByPID(pProcInfo, dwProcessCount, process.dwParentPID);

			if (dwParentIndex == -1 || lstrcmp(pProcInfo[dwParentIndex].szExeFile, "services.exe") != 0)
			{
				LOG_RULE(svchost, "svchost.exe should always have services.exe as its parent (Parent = %s)", pProcInfo[dwParentIndex].szExeFile);
				bRet = FALSE;
			}

			if (process.dwSessionId != 0 && process.dwSessionId != INVALID_SESSION_ID)
			{
				LOG_RULE(svchost, "svchost.exe should have SessionId 0 (SessionId = %d)", process.dwSessionId);
				bRet = FALSE;
			}

			if (process.dwBasePriority != 8)
			{
				LOG_RULE(svchost, "svchost.exe should have a base priority of 8 (Base Priority = %d)", process.dwBasePriority);
				bRet = FALSE;
			}

			LOG_RULE(svchost, "Status = %s (PID = %d)\n", bRet ? "PASSED" : "FAILED", process.dwPID);
		}
	}
	/* END RULE CHECKS */

	return bRet;
}

RULE_FUNCTION(lsm){
	BOOL bRet = TRUE; // Starts true, failures make this false
	char szOutPath[MAX_PATH];

	DWORD dwCount = GetCountByName(pProcInfo, dwProcessCount, "lsm.exe");

	if (dwCount != 1){
		LOG_RULE(lsm, "lsm.exe should exist one time (Count = %d)", dwCount);
	}

	for (unsigned int k = 0; k < dwProcessCount; k++, bRet = TRUE){
		if (lstrcmp("lsm.exe", pProcInfo[k].szExeFile) == 0){
			ProcInfo::ProcessInfo process = pProcInfo[k];

			LOG_RULE(lsm, "Starting rules for lsm.exe (PID = %d)", process.dwPID);

			/* START RULE CHECKS */
			char szFilepath[MAX_PATH];
			SYSTEM32_FILE("lsm.exe", szFilepath); // build our file path

			if (!ProcInfo::IsValidPath(process.dwPID, szFilepath, szOutPath, MAX_PATH)){
				LOG_RULE(lsm , "File is not located at: %s (Location = %s)", szFilepath, szOutPath);
				bRet = FALSE;
			}

			if (process.dwSessionId != 0 && process.dwSessionId != INVALID_SESSION_ID){
				LOG_RULE(lsm, "lsm.exe should have SessionId 0 (SessionId = %d)", process.dwSessionId);
				bRet = FALSE;
			}

			if (process.dwBasePriority != 8){
				LOG_RULE(lsm, "lsm.exe should have a base priority of 8 (Base Priority = %d)", process.dwBasePriority);
				bRet = FALSE;
			}
			/* END RULE CHECKS */

			LOG_RULE(lsm, "Status = %s (PID = %d)\n", bRet ? "PASSED" : "FAILED", process.dwPID);
		}
	}

	return bRet;
}

RULE_FUNCTION(winlogon){
	BOOL bRet = TRUE; // Starts true, failures make this false
	char szOutPath[MAX_PATH];
	DWORD dwCount = GetCountByName(pProcInfo, dwProcessCount, "winlogon.exe");

	if (dwCount != 1){
		LOG_RULE(winlogon, "winlogon.exe should exist one time (Count = %d)", dwCount);
	}

	for (unsigned int k = 0; k < dwProcessCount; k++, bRet = TRUE){
		if (lstrcmp("winlogon.exe", pProcInfo[k].szExeFile) == 0){
			ProcInfo::ProcessInfo process = pProcInfo[k];

			LOG_RULE(winlogon, "Starting rules for winlogon.exe (PID = %d)", process.dwPID);

			/* START RULE CHECKS */
			char szFilepath[MAX_PATH];
			SYSTEM32_FILE("winlogon.exe", szFilepath); // build our file path

			if (!ProcInfo::IsValidPath(process.dwPID, szFilepath, szOutPath, MAX_PATH)){
				LOG_RULE(winlogon, "File is not located at: %s (Location = %s)", szFilepath, szOutPath);
				bRet = FALSE;
			}

			if (process.dwSessionId != 1 && process.dwSessionId != INVALID_SESSION_ID){
				LOG_RULE(winlogon, "winlogon.exe should have SessionId 1 (SessionId = %d)", process.dwSessionId);
				bRet = FALSE;
			}

			if (process.dwBasePriority != 13){
				LOG_RULE(winlogon, "winlogon.exe should have a base priority of 13 (Base Priority = %d)", process.dwBasePriority);
				bRet = FALSE;
			}
			/* END RULE CHECKS */

			LOG_RULE(winlogon, "Status = %s (PID = %d)\n", bRet ? "PASSED" : "FAILED", process.dwPID);
		}
	}

	return bRet;
}

RULE_FUNCTION(explorer){
	BOOL bRet = TRUE; // Starts true, failures make this false
	char szOutPath[MAX_PATH];

	DWORD dwCount = GetCountByName(pProcInfo, dwProcessCount, "explorer.exe");
	
	if (dwCount != 1){
		LOG_RULE(explorer, "explorer.exe should exist one time (Count = %d)", dwCount);
	}

	for (unsigned int k = 0; k < dwProcessCount; k++, bRet = TRUE){
		if (lstrcmp("explorer.exe", pProcInfo[k].szExeFile) == 0){
			ProcInfo::ProcessInfo process = pProcInfo[k];

			LOG_RULE(explorer, "Starting rules for explorer.exe (PID = %d)", process.dwPID);

			/* START RULE CHECKS */
			char szFilepath[MAX_PATH];
			SYSTEMROOT_FILE("explorer.exe", szFilepath); // build our file path

			if (!ProcInfo::IsValidPath(process.dwPID, szFilepath, szOutPath, MAX_PATH)){
				LOG_RULE(explorer, "File is not located at: %s (Location = %s)", szFilepath, szOutPath);
				bRet = FALSE;
			}

			if (process.dwSessionId != 1 && process.dwSessionId != INVALID_SESSION_ID){
				LOG_RULE(explorer, "explorer.exe should have SessionId 1 (SessionId = %d)", process.dwSessionId);
				bRet = FALSE;
			}

			if (process.dwBasePriority != 8){
				LOG_RULE(explorer, "explorer.exe should have a base priority of 8 (Base Priority = %d)", process.dwBasePriority);
				bRet = FALSE;
			}
			/* END RULE CHECKS */
			LOG_RULE(explorer, "Status = %s (PID = %d)\n", bRet ? "PASSED" : "FAILED", process.dwPID);
		}
	}

	return bRet;
}

// TODO: Add similar name detection (e.g. scvhost.exe)
RULE_FUNCTION(anagram){
	BOOL bRet = TRUE;

	static TCHAR * pszMonitor[] = {
		"System",
		"smss.exe",
		"csrss.exe",
		"wininit.exe",
		"services.exe",
		"lsass.exe",
		"svchost.exe",
		"lsm.exe",
		"winlogon.exe",
		"explorer.exe",
	};

	static DWORD dwMonitorCount = sizeof(pszMonitor) / sizeof(TCHAR *);

	for (int i = 0; i < dwProcessCount; i++){
		for (int k = 0; k < dwMonitorCount; k++){
			if (IsDuplicateAnagram(pszMonitor[k], pProcInfo[i].szExeFile) && !ISMATCH(pszMonitor[k], pProcInfo[i].szExeFile))
			{
				LOG_RULE(anagram, "Warning - Process %s (PID = %d) is similar to %s", pProcInfo[i].szExeFile, pProcInfo[i].dwPID, pszMonitor[k]);
				bRet = FALSE;
			}
		}
	}

	return bRet;
}

RULE_FUNCTION(character_mismatch){
	BOOL bRet = TRUE;

	static TCHAR * pszMonitor[] = {
		"System",
		"smss.exe",
		"csrss.exe",
		"wininit.exe",
		"services.exe",
		"lsass.exe",
		"svchost.exe",
		"lsm.exe",
		"winlogon.exe",
		"explorer.exe",
	};

	static DWORD dwMonitorCount = sizeof(pszMonitor) / sizeof(TCHAR *);

	DWORD dwMismatch;

	for (int i = 0; i < dwProcessCount; i++){
		for (int k = 0; k < dwMonitorCount; k++){
			dwMismatch = 0;
			if ((dwMismatch = GetMismatchCount(pszMonitor[k], pProcInfo[i].szExeFile)) < 3 && !ISMATCH(pszMonitor[k], pProcInfo[i].szExeFile) && !IsInList(pProcInfo[i].szExeFile, pszMonitor, dwMonitorCount)){
				LOG_RULE(character mismatch, "Warning - Process %s (PID = %d) mismatches %s by %d characters", pProcInfo[i].szExeFile, pProcInfo[i].dwPID, pszMonitor[k], dwMismatch);
				bRet = FALSE;
			}
		}
	}

	return bRet;
}

// Getting user running a process:
//	1. OpenProcessToken (get the token)
//	2. GetTokenInformation w/ TokenOwner flag (get the SID)
//	3. LookupAccountSid (get the username)

void RunRules(ProcInfo::PProcessInfo pProcessInfo, DWORD dwProcessCount)
{
	zProcessRule rules[] = {
		RULE(system),		// System
		RULE(smss),			// smss.exe
		RULE(csrss),		// csrss.exe
		RULE(wininit),		// wininit.exe
		RULE(services),		// services.exe
		RULE(lsass),		// lsass.exe
		RULE(svchost),		// svchost.exe
		RULE(lsm),			// lsm.exe
		RULE(winlogon),		// winlogon.exe
		RULE(explorer),		// explorer.exe
		RULE(anagram),		// Checks for anagrams to known processes
		RULE(character_mismatch)	// Checks for total char mismatches for process names (for example: svchost.exe vs scvhost.exe)
	};

	DWORD dwRulesCount = sizeof(rules) / sizeof(zProcessRule);

	for (int k = 0; k < dwRulesCount; k++) {
		rules[k](pProcessInfo, dwProcessCount);
	}
}