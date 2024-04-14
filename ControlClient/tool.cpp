#include "tool.h"
#include "socketdata.h"


bool SetAutoStart(const std::string& programPath) {
    HKEY hKey;
    LSTATUS regStatus = RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey);
    if (regStatus != ERROR_SUCCESS) {
        std::cerr << "Failed to open registry key." << std::endl;
        return false;
    }

    regStatus = RegSetValueEx(hKey, "SK", 0, REG_SZ, reinterpret_cast<const BYTE*>(programPath.c_str()), static_cast<DWORD>(programPath.size()));
    if (regStatus != ERROR_SUCCESS) {
        std::cerr << "Failed to set registry value." << std::endl;
        RegCloseKey(hKey);
        return false;
    }

    RegCloseKey(hKey);
    std::cout << "Successfully set auto-start for program: " << programPath << std::endl;
    return true;
}


string GetCurrentProcessFileName() {
    char path[MAX_PATH];
    DWORD pathSize = GetModuleFileName(NULL, path, MAX_PATH);
    if (pathSize == 0) {
        std::cerr << "Failed to get the module file name." << std::endl;
        return "";
    }
    return string(path);
}



VOID DriverInstall(char* driverpath) {
    DWORD dwType = SERVICE_KERNEL_DRIVER;
    DWORD dwTag = 1;
    DWORD dwStart = SERVICE_BOOT_START;
    SHSetValue(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\services\\DriverFirstStart", TEXT("ImagePath"), REG_EXPAND_SZ, TEXT(driverpath), sizeof(TCHAR) * (lstrlen(TEXT(driverpath)) + 1));
    SHSetValue(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\services\\DriverFirstStart", TEXT("Group"), REG_EXPAND_SZ, TEXT("System Reserved"), sizeof(TCHAR) * (lstrlen(TEXT("System Reserved")) + 1));
    SHSetValue(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\services\\DriverFirstStart", TEXT("Start"), REG_DWORD, &dwStart, sizeof(DWORD));
    SHSetValue(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\services\\DriverFirstStart", TEXT("Type"), REG_DWORD, &dwType, sizeof(DWORD));
    SHSetValue(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\services\\DriverFirstStart", TEXT("Tag"), REG_DWORD, &dwTag, sizeof(DWORD));
}


void CheckSelf()
{
    //Hephaestus的哈希散列
    HANDLE hMutex = 0;
    hMutex = CreateMutexA(NULL, FALSE, "163f6cc5089f9fff0be8ccf063d3063bac85d3e3c57f84ccf67dd670758f0576");
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        exit(0);
    }
}



bool LoadDriver(const char* sysFilePath, const char* driverName)
{
    SC_HANDLE hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (hSCManager == nullptr)
    {
        std::cout << "Failed to open Service Control Manager" << std::endl;
        return false;
    }

    SC_HANDLE hService = CreateService(
        hSCManager,
        driverName,
        driverName,
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        sysFilePath,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr
    );

    if (hService == nullptr)
    {
        std::cout << "Failed to create service" << std::endl;
        CloseServiceHandle(hSCManager);
        return false;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    SC_HANDLE hSCManager2 = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (hSCManager2 == nullptr)
    {
        std::cout << "Failed to open Service Control Manager" << std::endl;
        return false;
    }

    SC_HANDLE hService2 = OpenService(hSCManager2, driverName, SERVICE_ALL_ACCESS);
    if (hService2 == nullptr)
    {
        std::cout << "Failed to open service" << std::endl;
        CloseServiceHandle(hSCManager2);
        return false;
    }

    bool result = StartService(hService2, 0, nullptr);
    if (!result)
    {
        std::cout << "Failed to start service" << std::endl;
        CloseServiceHandle(hService2);
        CloseServiceHandle(hSCManager2);
        return false;
    }

    CloseServiceHandle(hService2);
    CloseServiceHandle(hSCManager2);

    return true;
}








void ProtectSelf()
{
    ProtectProcess((char*)to_string(GetCurrentProcessId()).c_str());
}


void installnet()
{

    char PathBuffer[MAX_PATH];
    _getcwd(PathBuffer, sizeof(PathBuffer));
    strcat(PathBuffer, "\\NetFlt.sys");
    LoadDriver(PathBuffer, "NetFlt");
    DriverInstall(PathBuffer);
}

void installwpd()
{

	char PathBuffer[MAX_PATH];
	_getcwd(PathBuffer, sizeof(PathBuffer));
	strcat(PathBuffer, "\\WpdFlt.sys");
	LoadDriver(PathBuffer, "WpdFlt");
	DriverInstall(PathBuffer);
}

void installmouse()
{

	char PathBuffer[MAX_PATH];
	_getcwd(PathBuffer, sizeof(PathBuffer));
	strcat(PathBuffer, "\\MouseFlt.sys");
	LoadDriver(PathBuffer, "MouseFlt");
	DriverInstall(PathBuffer);
}

void installReg()
{

	char PathBuffer[MAX_PATH];
	_getcwd(PathBuffer, sizeof(PathBuffer));
	strcat(PathBuffer, "\\RegistryFilter.sys");
	LoadDriver(PathBuffer, "RegistryFilter");
	DriverInstall(PathBuffer);
}

void installusbflt()
{

    char PathBuffer[MAX_PATH];
    _getcwd(PathBuffer, sizeof(PathBuffer));
    strcat(PathBuffer, "\\FltUsb.sys");
    LoadDriver(PathBuffer, "FltUsb");
    DriverInstall(PathBuffer);
}


void startRegflt()
{
	char PathBuffer[MAX_PATH];
	_getcwd(PathBuffer, sizeof(PathBuffer));
	strcat(PathBuffer, "\\RegFltMessager.exe");
	// 要执行的可执行文件的路径
	LPCSTR applicationName = PathBuffer;

	// 命令行参数
	LPSTR commandLineArgs = nullptr;

	// 进程的安全属性
	LPSECURITY_ATTRIBUTES processAttributes = nullptr;

	// 线程的安全属性
	LPSECURITY_ATTRIBUTES threadAttributes = nullptr;

	// 指示新进程是否从调用进程继承其句柄
	BOOL inheritHandles = FALSE;

	// 创建进程的标志
	DWORD creationFlags = 0;

	// 环境块
	LPVOID environment = nullptr;

	// 当前目录
	LPCSTR currentDirectory = nullptr;

	// STARTUPINFO 结构体，用于指定新进程的主窗口的外观
	STARTUPINFOA startupInfo;
	ZeroMemory(&startupInfo, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);

	// PROCESS_INFORMATION 结构体，用于获取新进程的信息
	PROCESS_INFORMATION processInfo;
	ZeroMemory(&processInfo, sizeof(processInfo));

	// 创建新的进程
	if (CreateProcessA(applicationName, commandLineArgs, processAttributes, threadAttributes, inheritHandles, creationFlags, environment, currentDirectory, &startupInfo, &processInfo)) {
		std::cout << "新进程创建成功！" << std::endl;
		std::cout << "新进程的进程ID：" << processInfo.dwProcessId << std::endl;
		std::cout << "新进程的主线程ID：" << processInfo.dwThreadId << std::endl;
	}

	int code = GetLastError();
}


void startFlieflt()
{
	char PathBuffer[MAX_PATH];
	_getcwd(PathBuffer, sizeof(PathBuffer));
	strcat(PathBuffer, "\\FileMessager.exe");
	// 要执行的可执行文件的路径
	LPCSTR applicationName = PathBuffer;

	// 命令行参数
	LPSTR commandLineArgs = nullptr;

	// 进程的安全属性
	LPSECURITY_ATTRIBUTES processAttributes = nullptr;

	// 线程的安全属性
	LPSECURITY_ATTRIBUTES threadAttributes = nullptr;

	// 指示新进程是否从调用进程继承其句柄
	BOOL inheritHandles = FALSE;

	// 创建进程的标志
	DWORD creationFlags = 0;

	// 环境块
	LPVOID environment = nullptr;

	// 当前目录
	LPCSTR currentDirectory = nullptr;

	// STARTUPINFO 结构体，用于指定新进程的主窗口的外观
	STARTUPINFOA startupInfo;
	ZeroMemory(&startupInfo, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);

	// PROCESS_INFORMATION 结构体，用于获取新进程的信息
	PROCESS_INFORMATION processInfo;
	ZeroMemory(&processInfo, sizeof(processInfo));

	// 创建新的进程
	if (CreateProcessA(applicationName, commandLineArgs, processAttributes, threadAttributes, inheritHandles, creationFlags, environment, currentDirectory, &startupInfo, &processInfo)) {
		std::cout << "新进程创建成功！" << std::endl;
		std::cout << "新进程的进程ID：" << processInfo.dwProcessId << std::endl;
		std::cout << "新进程的主线程ID：" << processInfo.dwThreadId << std::endl;
	}

	int code = GetLastError();

}

void InitSelf()
{
    
    CheckSelf();
    char PathBuffer[MAX_PATH];
    _getcwd(PathBuffer, sizeof(PathBuffer));
    strcat(PathBuffer, "\\R0sys.sys");
    LoadDriver(PathBuffer, "Hephaestus");
    DriverInstall(PathBuffer);
    installnet();
	installwpd();
	installmouse();
	InstallMiniFilterDriver("Minifilter", ".\\Minifilter.sys", "370100");
	InstallRegFilterDriver("RegistryFilter", ".\\RegistryFilter.sys","370123");
	StartMiniFilterDriver("Minifilter");
	StartRegFilterDriver("RegistryFilter");

    ProtectSelf();
    SetAutoStart(GetCurrentProcessFileName());
	startRegflt();
	startFlieflt();
}


char* GetIPAddress(const char* domain) {


	// 执行 DNS 查询
	hostent* host = gethostbyname(domain);
	if (host != NULL && host->h_addr_list[0] != NULL) {
		in_addr addr;
		memcpy(&addr, host->h_addr_list[0], sizeof(in_addr));
		return _strdup(inet_ntoa(addr));
	}
	else {
		return _strdup("N");
	}
}


DWORD SetAllAdaptersIpAddresses() {
	HKEY hKey;
	DWORD dwValue = 0;

	// 打开注册表项
	LONG lResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters", 0, KEY_SET_VALUE, &hKey);
	if (lResult != ERROR_SUCCESS) {
		std::cerr << "Failed to open registry key." << std::endl;
		return false;
	}

	// 设置 DisabledComponents 的值为 0xffffffff（禁用 IPv6）
	lResult = RegSetValueExW(hKey, L"DisabledComponents", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dwValue), sizeof(dwValue));
	if (lResult != ERROR_SUCCESS) {
		std::cerr << "Failed to set registry value." << std::endl;
		RegCloseKey(hKey);
		return false;
	}

	// 关闭注册表项
	RegCloseKey(hKey);

}


BOOL InstallRegFilterDriver(const char* lpszDriverName, const char* lpszDriverPath, const char* lpszAltitude)
{
	char    szTempStr[MAX_PATH];
	HKEY    hKey;
	DWORD    dwData;
	char    szDriverImagePath[MAX_PATH];

	if (NULL == lpszDriverName || NULL == lpszDriverPath)
	{
		return FALSE;
	}
	//得到完整的驱动路径
	GetFullPathName(lpszDriverPath, MAX_PATH, szDriverImagePath, NULL);

	SC_HANDLE hServiceMgr = NULL;// SCM管理器的句柄
	SC_HANDLE hService = NULL;// NT驱动程序的服务句柄

	//打开服务控制管理器
	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hServiceMgr == NULL)
	{
		// OpenSCManager失败
		CloseServiceHandle(hServiceMgr);
		return FALSE;
	}

	// OpenSCManager成功  

	//创建驱动所对应的服务
	hService = CreateService(hServiceMgr,
		lpszDriverName,             // 驱动程序的在注册表中的名字
		lpszDriverName,             // 注册表驱动程序的DisplayName 值
		SERVICE_ALL_ACCESS,         // 加载驱动程序的访问权限
		SERVICE_FILE_SYSTEM_DRIVER, // 表示加载的服务是文件系统驱动程序
		SERVICE_DEMAND_START,       // 注册表驱动程序的Start 值
		SERVICE_ERROR_IGNORE,       // 注册表驱动程序的ErrorControl 值
		szDriverImagePath,          // 注册表驱动程序的ImagePath 值
		"FSFilter Activity Monitor",// 注册表驱动程序的Group 值
		NULL,
		"FltMgr",                   // 注册表驱动程序的DependOnService 值
		NULL,
		NULL);

	if (hService == NULL)
	{
		if (GetLastError() == ERROR_SERVICE_EXISTS)
		{
			//服务创建失败，是由于服务已经创立过
			CloseServiceHandle(hService);       // 服务句柄
			CloseServiceHandle(hServiceMgr);    // SCM句柄
			return TRUE;
		}
		else
		{
			CloseServiceHandle(hService);       // 服务句柄
			CloseServiceHandle(hServiceMgr);    // SCM句柄
			return FALSE;
		}
	}
	CloseServiceHandle(hService);       // 服务句柄
	CloseServiceHandle(hServiceMgr);    // SCM句柄

	//-------------------------------------------------------------------------------------------------------
	// SYSTEM\\CurrentControlSet\\Services\\DriverName\\Instances子健下的键值项 
	//-------------------------------------------------------------------------------------------------------
	strcpy(szTempStr, "SYSTEM\\CurrentControlSet\\Services\\");
	strcat(szTempStr, lpszDriverName);
	strcat(szTempStr, "\\Instances");
	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szTempStr, 0, (LPSTR)"", REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, (LPDWORD)&dwData) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	// 注册表驱动程序的DefaultInstance 值 
	strcpy(szTempStr, lpszDriverName);
	strcat(szTempStr, " Instance");
	if (RegSetValueEx(hKey, "DefaultInstance", 0, REG_SZ, (CONST BYTE*)szTempStr, (DWORD)strlen(szTempStr)) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	RegFlushKey(hKey);//刷新注册表
	RegCloseKey(hKey);


	//-------------------------------------------------------------------------------------------------------
	// SYSTEM\\CurrentControlSet\\Services\\DriverName\\Instances\\DriverName Instance子健下的键值项 
	//-------------------------------------------------------------------------------------------------------
	strcpy(szTempStr, "SYSTEM\\CurrentControlSet\\Services\\");
	strcat(szTempStr, lpszDriverName);
	strcat(szTempStr, "\\Instances\\");
	strcat(szTempStr, lpszDriverName);
	strcat(szTempStr, " Instance");
	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szTempStr, 0, (LPSTR)"", REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, (LPDWORD)&dwData) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	// 注册表驱动程序的Altitude 值
	strcpy(szTempStr, lpszAltitude);
	if (RegSetValueEx(hKey, "Altitude", 0, REG_SZ, (CONST BYTE*)szTempStr, (DWORD)strlen(szTempStr)) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	// 注册表驱动程序的Flags 值
	dwData = 0x0;
	if (RegSetValueEx(hKey, "Flags", 0, REG_DWORD, (CONST BYTE*) & dwData, sizeof(DWORD)) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	RegFlushKey(hKey);//刷新注册表
	RegCloseKey(hKey);

	return TRUE;
}

BOOL InstallMiniFilterDriver(const char* lpszDriverName, const char* lpszDriverPath, const char* lpszAltitude)
{
	char    szTempStr[MAX_PATH];
	HKEY    hKey;
	DWORD    dwData;
	char    szDriverImagePath[MAX_PATH];

	if (NULL == lpszDriverName || NULL == lpszDriverPath)
	{
		return FALSE;
	}
	//得到完整的驱动路径
	GetFullPathName(lpszDriverPath, MAX_PATH, szDriverImagePath, NULL);

	SC_HANDLE hServiceMgr = NULL;// SCM管理器的句柄
	SC_HANDLE hService = NULL;// NT驱动程序的服务句柄

	//打开服务控制管理器
	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hServiceMgr == NULL)
	{
		// OpenSCManager失败
		CloseServiceHandle(hServiceMgr);
		return FALSE;
	}

	// OpenSCManager成功  

	//创建驱动所对应的服务
	hService = CreateService(hServiceMgr,
		lpszDriverName,             // 驱动程序的在注册表中的名字
		lpszDriverName,             // 注册表驱动程序的DisplayName 值
		SERVICE_ALL_ACCESS,         // 加载驱动程序的访问权限
		SERVICE_FILE_SYSTEM_DRIVER, // 表示加载的服务是文件系统驱动程序
		SERVICE_DEMAND_START,       // 注册表驱动程序的Start 值
		SERVICE_ERROR_IGNORE,       // 注册表驱动程序的ErrorControl 值
		szDriverImagePath,          // 注册表驱动程序的ImagePath 值
		"FSFilter Activity Monitor",// 注册表驱动程序的Group 值
		NULL,
		"FltMgr",                   // 注册表驱动程序的DependOnService 值
		NULL,
		NULL);

	if (hService == NULL)
	{
		if (GetLastError() == ERROR_SERVICE_EXISTS)
		{
			//服务创建失败，是由于服务已经创立过
			CloseServiceHandle(hService);       // 服务句柄
			CloseServiceHandle(hServiceMgr);    // SCM句柄
			return TRUE;
		}
		else
		{
			CloseServiceHandle(hService);       // 服务句柄
			CloseServiceHandle(hServiceMgr);    // SCM句柄
			return FALSE;
		}
	}
	CloseServiceHandle(hService);       // 服务句柄
	CloseServiceHandle(hServiceMgr);    // SCM句柄

	//-------------------------------------------------------------------------------------------------------
	// SYSTEM\\CurrentControlSet\\Services\\DriverName\\Instances子健下的键值项 
	//-------------------------------------------------------------------------------------------------------
	strcpy(szTempStr, "SYSTEM\\CurrentControlSet\\Services\\");
	strcat(szTempStr, lpszDriverName);
	strcat(szTempStr, "\\Instances");
	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szTempStr, 0, (LPSTR)"", REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, (LPDWORD)&dwData) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	// 注册表驱动程序的DefaultInstance 值 
	strcpy(szTempStr, lpszDriverName);
	strcat(szTempStr, " Instance");
	if (RegSetValueEx(hKey, "DefaultInstance", 0, REG_SZ, (CONST BYTE*)szTempStr, (DWORD)strlen(szTempStr)) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	RegFlushKey(hKey);//刷新注册表
	RegCloseKey(hKey);


	//-------------------------------------------------------------------------------------------------------
	// SYSTEM\\CurrentControlSet\\Services\\DriverName\\Instances\\DriverName Instance子健下的键值项 
	//-------------------------------------------------------------------------------------------------------
	strcpy(szTempStr, "SYSTEM\\CurrentControlSet\\Services\\");
	strcat(szTempStr, lpszDriverName);
	strcat(szTempStr, "\\Instances\\");
	strcat(szTempStr, lpszDriverName);
	strcat(szTempStr, " Instance");
	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szTempStr, 0, (LPSTR)"", REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, (LPDWORD)&dwData) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	// 注册表驱动程序的Altitude 值
	strcpy(szTempStr, lpszAltitude);
	if (RegSetValueEx(hKey, "Altitude", 0, REG_SZ, (CONST BYTE*)szTempStr, (DWORD)strlen(szTempStr)) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	// 注册表驱动程序的Flags 值
	dwData = 0x0;
	if (RegSetValueEx(hKey, "Flags", 0, REG_DWORD, (CONST BYTE*) & dwData, sizeof(DWORD)) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	RegFlushKey(hKey);//刷新注册表
	RegCloseKey(hKey);

	return TRUE;
}

BOOL StartMiniFilterDriver(const char* lpszDriverName)
{
	SC_HANDLE        schManager;
	SC_HANDLE        schService;

	if (NULL == lpszDriverName)
	{
		return FALSE;
	}

	schManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == schManager)
	{
		CloseServiceHandle(schManager);
		return FALSE;
	}
	schService = OpenService(schManager, lpszDriverName, SERVICE_ALL_ACCESS);
	if (NULL == schService)
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schManager);
		return FALSE;
	}

	if (!StartService(schService, 0, NULL))
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schManager);
		if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
		{
			// 服务已经开启
			return TRUE;
		}
		return FALSE;
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schManager);

	return TRUE;
}

BOOL StartRegFilterDriver(const char* lpszDriverName)
{
	SC_HANDLE        schManager;
	SC_HANDLE        schService;

	if (NULL == lpszDriverName)
	{
		return FALSE;
	}

	schManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == schManager)
	{
		CloseServiceHandle(schManager);
		return FALSE;
	}
	schService = OpenService(schManager, lpszDriverName, SERVICE_ALL_ACCESS);
	if (NULL == schService)
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schManager);
		return FALSE;
	}

	if (!StartService(schService, 0, NULL))
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schManager);
		if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
		{
			// 服务已经开启
			return TRUE;
		}
		return FALSE;
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schManager);

	return TRUE;
}