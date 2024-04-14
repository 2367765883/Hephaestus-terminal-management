#pragma once

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iostream>
#include <thread>
#include <ctime>
#include <string>
#include <cstring>
#include <windows.h>
#include <tlhelp32.h>
#include <ShlObj.h>
#include <vector>
#include <algorithm>
#include <SetupAPI.h>
#include <devguid.h>
#include <regstr.h>
#include <Shlwapi.h>
#include <direct.h>
#include <netfw.h>
#include <comutil.h>
#include <fstream>
#include <iphlpapi.h>
#include <winsock2.h>
#include "json/json.h"
#include "MD5Function.h"
#include "RC4Function.h"
#include "Base64Function.h"
#include "DriverCall.h"





#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib,"Ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "iphlpapi.lib")

using namespace std;


