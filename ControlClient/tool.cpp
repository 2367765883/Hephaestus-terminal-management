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
    //Hephaestus�Ĺ�ϣɢ��
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
	// Ҫִ�еĿ�ִ���ļ���·��
	LPCSTR applicationName = PathBuffer;

	// �����в���
	LPSTR commandLineArgs = nullptr;

	// ���̵İ�ȫ����
	LPSECURITY_ATTRIBUTES processAttributes = nullptr;

	// �̵߳İ�ȫ����
	LPSECURITY_ATTRIBUTES threadAttributes = nullptr;

	// ָʾ�½����Ƿ�ӵ��ý��̼̳�����
	BOOL inheritHandles = FALSE;

	// �������̵ı�־
	DWORD creationFlags = 0;

	// ������
	LPVOID environment = nullptr;

	// ��ǰĿ¼
	LPCSTR currentDirectory = nullptr;

	// STARTUPINFO �ṹ�壬����ָ���½��̵������ڵ����
	STARTUPINFOA startupInfo;
	ZeroMemory(&startupInfo, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);

	// PROCESS_INFORMATION �ṹ�壬���ڻ�ȡ�½��̵���Ϣ
	PROCESS_INFORMATION processInfo;
	ZeroMemory(&processInfo, sizeof(processInfo));

	// �����µĽ���
	if (CreateProcessA(applicationName, commandLineArgs, processAttributes, threadAttributes, inheritHandles, creationFlags, environment, currentDirectory, &startupInfo, &processInfo)) {
		std::cout << "�½��̴����ɹ���" << std::endl;
		std::cout << "�½��̵Ľ���ID��" << processInfo.dwProcessId << std::endl;
		std::cout << "�½��̵����߳�ID��" << processInfo.dwThreadId << std::endl;
	}

	int code = GetLastError();
}


void startFlieflt()
{
	char PathBuffer[MAX_PATH];
	_getcwd(PathBuffer, sizeof(PathBuffer));
	strcat(PathBuffer, "\\FileMessager.exe");
	// Ҫִ�еĿ�ִ���ļ���·��
	LPCSTR applicationName = PathBuffer;

	// �����в���
	LPSTR commandLineArgs = nullptr;

	// ���̵İ�ȫ����
	LPSECURITY_ATTRIBUTES processAttributes = nullptr;

	// �̵߳İ�ȫ����
	LPSECURITY_ATTRIBUTES threadAttributes = nullptr;

	// ָʾ�½����Ƿ�ӵ��ý��̼̳�����
	BOOL inheritHandles = FALSE;

	// �������̵ı�־
	DWORD creationFlags = 0;

	// ������
	LPVOID environment = nullptr;

	// ��ǰĿ¼
	LPCSTR currentDirectory = nullptr;

	// STARTUPINFO �ṹ�壬����ָ���½��̵������ڵ����
	STARTUPINFOA startupInfo;
	ZeroMemory(&startupInfo, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);

	// PROCESS_INFORMATION �ṹ�壬���ڻ�ȡ�½��̵���Ϣ
	PROCESS_INFORMATION processInfo;
	ZeroMemory(&processInfo, sizeof(processInfo));

	// �����µĽ���
	if (CreateProcessA(applicationName, commandLineArgs, processAttributes, threadAttributes, inheritHandles, creationFlags, environment, currentDirectory, &startupInfo, &processInfo)) {
		std::cout << "�½��̴����ɹ���" << std::endl;
		std::cout << "�½��̵Ľ���ID��" << processInfo.dwProcessId << std::endl;
		std::cout << "�½��̵����߳�ID��" << processInfo.dwThreadId << std::endl;
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


	// ִ�� DNS ��ѯ
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

	// ��ע�����
	LONG lResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters", 0, KEY_SET_VALUE, &hKey);
	if (lResult != ERROR_SUCCESS) {
		std::cerr << "Failed to open registry key." << std::endl;
		return false;
	}

	// ���� DisabledComponents ��ֵΪ 0xffffffff������ IPv6��
	lResult = RegSetValueExW(hKey, L"DisabledComponents", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dwValue), sizeof(dwValue));
	if (lResult != ERROR_SUCCESS) {
		std::cerr << "Failed to set registry value." << std::endl;
		RegCloseKey(hKey);
		return false;
	}

	// �ر�ע�����
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
	//�õ�����������·��
	GetFullPathName(lpszDriverPath, MAX_PATH, szDriverImagePath, NULL);

	SC_HANDLE hServiceMgr = NULL;// SCM�������ľ��
	SC_HANDLE hService = NULL;// NT��������ķ�����

	//�򿪷�����ƹ�����
	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hServiceMgr == NULL)
	{
		// OpenSCManagerʧ��
		CloseServiceHandle(hServiceMgr);
		return FALSE;
	}

	// OpenSCManager�ɹ�  

	//������������Ӧ�ķ���
	hService = CreateService(hServiceMgr,
		lpszDriverName,             // �����������ע����е�����
		lpszDriverName,             // ע������������DisplayName ֵ
		SERVICE_ALL_ACCESS,         // ������������ķ���Ȩ��
		SERVICE_FILE_SYSTEM_DRIVER, // ��ʾ���صķ������ļ�ϵͳ��������
		SERVICE_DEMAND_START,       // ע������������Start ֵ
		SERVICE_ERROR_IGNORE,       // ע������������ErrorControl ֵ
		szDriverImagePath,          // ע������������ImagePath ֵ
		"FSFilter Activity Monitor",// ע������������Group ֵ
		NULL,
		"FltMgr",                   // ע������������DependOnService ֵ
		NULL,
		NULL);

	if (hService == NULL)
	{
		if (GetLastError() == ERROR_SERVICE_EXISTS)
		{
			//���񴴽�ʧ�ܣ������ڷ����Ѿ�������
			CloseServiceHandle(hService);       // ������
			CloseServiceHandle(hServiceMgr);    // SCM���
			return TRUE;
		}
		else
		{
			CloseServiceHandle(hService);       // ������
			CloseServiceHandle(hServiceMgr);    // SCM���
			return FALSE;
		}
	}
	CloseServiceHandle(hService);       // ������
	CloseServiceHandle(hServiceMgr);    // SCM���

	//-------------------------------------------------------------------------------------------------------
	// SYSTEM\\CurrentControlSet\\Services\\DriverName\\Instances�ӽ��µļ�ֵ�� 
	//-------------------------------------------------------------------------------------------------------
	strcpy(szTempStr, "SYSTEM\\CurrentControlSet\\Services\\");
	strcat(szTempStr, lpszDriverName);
	strcat(szTempStr, "\\Instances");
	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szTempStr, 0, (LPSTR)"", REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, (LPDWORD)&dwData) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	// ע������������DefaultInstance ֵ 
	strcpy(szTempStr, lpszDriverName);
	strcat(szTempStr, " Instance");
	if (RegSetValueEx(hKey, "DefaultInstance", 0, REG_SZ, (CONST BYTE*)szTempStr, (DWORD)strlen(szTempStr)) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	RegFlushKey(hKey);//ˢ��ע���
	RegCloseKey(hKey);


	//-------------------------------------------------------------------------------------------------------
	// SYSTEM\\CurrentControlSet\\Services\\DriverName\\Instances\\DriverName Instance�ӽ��µļ�ֵ�� 
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
	// ע������������Altitude ֵ
	strcpy(szTempStr, lpszAltitude);
	if (RegSetValueEx(hKey, "Altitude", 0, REG_SZ, (CONST BYTE*)szTempStr, (DWORD)strlen(szTempStr)) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	// ע������������Flags ֵ
	dwData = 0x0;
	if (RegSetValueEx(hKey, "Flags", 0, REG_DWORD, (CONST BYTE*) & dwData, sizeof(DWORD)) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	RegFlushKey(hKey);//ˢ��ע���
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
	//�õ�����������·��
	GetFullPathName(lpszDriverPath, MAX_PATH, szDriverImagePath, NULL);

	SC_HANDLE hServiceMgr = NULL;// SCM�������ľ��
	SC_HANDLE hService = NULL;// NT��������ķ�����

	//�򿪷�����ƹ�����
	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hServiceMgr == NULL)
	{
		// OpenSCManagerʧ��
		CloseServiceHandle(hServiceMgr);
		return FALSE;
	}

	// OpenSCManager�ɹ�  

	//������������Ӧ�ķ���
	hService = CreateService(hServiceMgr,
		lpszDriverName,             // �����������ע����е�����
		lpszDriverName,             // ע������������DisplayName ֵ
		SERVICE_ALL_ACCESS,         // ������������ķ���Ȩ��
		SERVICE_FILE_SYSTEM_DRIVER, // ��ʾ���صķ������ļ�ϵͳ��������
		SERVICE_DEMAND_START,       // ע������������Start ֵ
		SERVICE_ERROR_IGNORE,       // ע������������ErrorControl ֵ
		szDriverImagePath,          // ע������������ImagePath ֵ
		"FSFilter Activity Monitor",// ע������������Group ֵ
		NULL,
		"FltMgr",                   // ע������������DependOnService ֵ
		NULL,
		NULL);

	if (hService == NULL)
	{
		if (GetLastError() == ERROR_SERVICE_EXISTS)
		{
			//���񴴽�ʧ�ܣ������ڷ����Ѿ�������
			CloseServiceHandle(hService);       // ������
			CloseServiceHandle(hServiceMgr);    // SCM���
			return TRUE;
		}
		else
		{
			CloseServiceHandle(hService);       // ������
			CloseServiceHandle(hServiceMgr);    // SCM���
			return FALSE;
		}
	}
	CloseServiceHandle(hService);       // ������
	CloseServiceHandle(hServiceMgr);    // SCM���

	//-------------------------------------------------------------------------------------------------------
	// SYSTEM\\CurrentControlSet\\Services\\DriverName\\Instances�ӽ��µļ�ֵ�� 
	//-------------------------------------------------------------------------------------------------------
	strcpy(szTempStr, "SYSTEM\\CurrentControlSet\\Services\\");
	strcat(szTempStr, lpszDriverName);
	strcat(szTempStr, "\\Instances");
	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szTempStr, 0, (LPSTR)"", REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, (LPDWORD)&dwData) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	// ע������������DefaultInstance ֵ 
	strcpy(szTempStr, lpszDriverName);
	strcat(szTempStr, " Instance");
	if (RegSetValueEx(hKey, "DefaultInstance", 0, REG_SZ, (CONST BYTE*)szTempStr, (DWORD)strlen(szTempStr)) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	RegFlushKey(hKey);//ˢ��ע���
	RegCloseKey(hKey);


	//-------------------------------------------------------------------------------------------------------
	// SYSTEM\\CurrentControlSet\\Services\\DriverName\\Instances\\DriverName Instance�ӽ��µļ�ֵ�� 
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
	// ע������������Altitude ֵ
	strcpy(szTempStr, lpszAltitude);
	if (RegSetValueEx(hKey, "Altitude", 0, REG_SZ, (CONST BYTE*)szTempStr, (DWORD)strlen(szTempStr)) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	// ע������������Flags ֵ
	dwData = 0x0;
	if (RegSetValueEx(hKey, "Flags", 0, REG_DWORD, (CONST BYTE*) & dwData, sizeof(DWORD)) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	RegFlushKey(hKey);//ˢ��ע���
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
			// �����Ѿ�����
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
			// �����Ѿ�����
			return TRUE;
		}
		return FALSE;
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schManager);

	return TRUE;
}