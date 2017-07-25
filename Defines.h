/*
	Common includes / macros for other files to use
*/

#ifndef _DEFINES_H_
	#define _DEFINES_H_

#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#define ISMATCH(str1, str2) ( lstrcmp(str1, str2) == 0 )

#endif