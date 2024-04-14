#include <WinSock2.h>
#include <WS2tcpip.h>
#include <windows.h>
#include <fltUser.h>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <locale>
#include <codecvt>
#include <fstream>
#include <string>
#include <cstdlib>
#include <cstring>
#include <unordered_map>
#include <iomanip>
#include <sstream>
#include <wincrypt.h>
#include <mutex>

#define  BUFFER_SIZE 1024
#define  TIME_FORMAT "%Y-%m-%d-%H%M%S"

#define  SYMBOLIC_NAME "\\\\.\\sym_name"
#define NETSYM_NAME "\\\\.\\sknetflt"
#define _USB_SYS_NAME "\\\\.\\usbsysmblicname"
#define CTL_CODE_BASE 0x8000
#define CTL_CMD(i) CTL_CODE(FILE_DEVICE_UNKNOWN,CTL_CODE_BASE+i,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define  CTL_PROT CTL_CMD(1)
#define  CTL_KILL CTL_CMD(2)
#define  CTL_UNPROT CTL_CMD(3)
#define  CTL_ADDDLL CTL_CMD(4)
#define  CTL_DELDLL CTL_CMD(5)
#define  CTL_DELFILE CTL_CMD(6)
#define  CTL_PROTECT_FILE CTL_CMD(7)
#define  CTL_DISABLE_DEBUG CTL_CMD(8)
#define  CTL_ENABLE_DEBUG CTL_CMD(9)
#define  CTL_ADDFILE CTL_CMD(10)
#define  CTL_DELFILENAME CTL_CMD(11)
#define  CTL_BLOCK CTL_CMD(12)
#define  CTL_REMOVEBLOCK CTL_CMD(13)
#define  CTL_BLOCKUSB CTL_CMD(14)
#define  CTL_ALLOWUSB CTL_CMD(15)



#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" ) 

#pragma comment(lib, "FltLib.lib")
#pragma comment(lib,"Ws2_32.lib")


using namespace std;


std::mutex g_mtx;

_WINSOCK2API_::WSADATA SockData;
_WINSOCK2API_::SOCKET talksock;
_WINSOCK2API_::sockaddr_in saSrv;
_WINSOCK2API_::sockaddr_in saClt;




vector<string> g_UserRules;

BOOL g_bWriteLogFlag = FALSE;

char timebuffer[80] = {0};

// 接收内核层发送过来的文件句柄
typedef struct _MY_STRUCTURE {
	UCHAR Filename[512];
	ULONG uPid;
} MY_STRUCTURE;

// 应用层发送数据的结构体
typedef struct _GET_BUFF_ {
	FILTER_REPLY_HEADER Header;
	MY_STRUCTURE Data;
} GET_BUFF, * PGET_BUFF;

typedef struct _REPLY_STRUCT_ {
	FILTER_REPLY_HEADER Header;
	CHAR Flag;
} REPLY_STRUCT, * PREPLY_STRUCT;


void ProtectProcess(char* pids)
{
	HANDLE hDevice = NULL;
	DWORD retlen = NULL;
	hDevice = CreateFileA(SYMBOLIC_NAME, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DeviceIoControl(hDevice, CTL_PROT, pids, strlen(pids), NULL, 0, &retlen, NULL);
	CloseHandle(hDevice);
}

const char* getCurrentTime(const char* format) {
	
	

	ZeroMemory(timebuffer, 80);

	std::time_t currentTime = std::time(nullptr);

	
	std::tm* localTime = std::localtime(&currentTime);

	
	const int bufferSize = 80; 
	

	std::strftime(timebuffer, bufferSize, format, localTime);

	return timebuffer;
}



bool IsDirectory(const std::wstring& path) {
	DWORD attributes = GetFileAttributesW(path.c_str());
	return (attributes != INVALID_FILE_ATTRIBUTES &&
		(attributes & FILE_ATTRIBUTE_DIRECTORY));
}


wchar_t* ConvertToWide(const char* narrowStr) {
	if (narrowStr == nullptr) {
		return nullptr;
	}

	size_t length = mbstowcs(NULL, narrowStr, 0);
	if (length == (size_t)-1) {
		std::cerr << "Failed to determine string length." << std::endl;
		return nullptr;
	}

	wchar_t* wideStr = new wchar_t[length + 1]; // 分配足够的空间
	mbstowcs(wideStr, narrowStr, length + 1);

	return wideStr;
}


string wstring2string(wstring wstr)
{
	string result;
	//获取缓冲区大小，并申请空间，缓冲区大小事按字节计算的  
	int len = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), wstr.size(), NULL, 0, NULL, NULL);
	char* buffer = new char[len + 1];
	//宽字节编码转换成多字节编码  
	WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), wstr.size(), buffer, len, NULL, NULL);
	buffer[len] = '\0';
	//删除缓冲区并返回值  
	result.append(buffer);
	delete[] buffer;
	return result;
}




void appendToFile(const std::string& str) {
	
	// 打开文件以追加模式写入，如果文件不存在则创建文件
	std::ofstream outputFile;

	wchar_t buffer[MAX_PATH];
	GetModuleFileNameW(NULL, buffer, MAX_PATH);

	std::wstring modulePath(buffer);
	std::wstring::size_type pos = modulePath.find_last_of(L"\\");
	std::wstring currentDirectory = modulePath.substr(0, pos);

	std::string logname = wstring2string(currentDirectory) + "\\hptslogs\\" + getCurrentTime(TIME_FORMAT)+".hptslog";

	printf("name:%s\n", logname.c_str());

	outputFile.open(logname, std::ios_base::app | std::ios_base::out);

	if (!outputFile.is_open()) {
		std::cerr << "无法打开文件！" << std::endl;
		return;
	}

	// 写入字符串到文件
	outputFile << str;

	// 关闭文件
	outputFile.close();
}

std::string CalculateFileHash(const std::string& filePath)
{
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	DWORD bytesRead = 0;
	BYTE buffer[1024];
	DWORD dwSize = sizeof(buffer);
	DWORD dwHashLen = 0;
	std::stringstream ss;


	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		std::cerr << "Error in CryptAcquireContext: " << GetLastError() << std::endl;
		return "";
	}

	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
	{
		std::cerr << "Error in CryptCreateHash: " << GetLastError() << std::endl;
		CryptReleaseContext(hProv, 0);
		return "";
	}


	HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		std::cerr << "Error opening file: " << GetLastError() << std::endl;
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return "";
	}


	while (ReadFile(hFile, buffer, dwSize, &bytesRead, NULL))
	{
		if (bytesRead == 0)
			break;
		if (!CryptHashData(hHash, buffer, bytesRead, 0))
		{
			std::cerr << "Error in CryptHashData: " << GetLastError() << std::endl;
			CloseHandle(hFile);
			CryptDestroyHash(hHash);
			CryptReleaseContext(hProv, 0);
			return "";
		}
	}

	if (!CryptGetHashParam(hHash, HP_HASHVAL, NULL, &dwHashLen, 0))
	{
		std::cerr << "Error in CryptGetHashParam (getting hash length): " << GetLastError() << std::endl;
		CloseHandle(hFile);
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return "";
	}


	BYTE* pbHash = (BYTE*)malloc(dwHashLen);
	if (pbHash == NULL)
	{
		std::cerr << "Error allocating memory for hash: " << GetLastError() << std::endl;
		CloseHandle(hFile);
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return "";
	}


	if (!CryptGetHashParam(hHash, HP_HASHVAL, pbHash, &dwHashLen, 0))
	{
		std::cerr << "Error in CryptGetHashParam (getting hash value): " << GetLastError() << std::endl;
		CloseHandle(hFile);
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		free(pbHash);
		return "";
	}


	for (DWORD i = 0; i < dwHashLen; i++)
	{
		ss << std::hex << std::setw(2) << std::setfill('0') << (int)pbHash[i];
	}


	free(pbHash);
	CloseHandle(hFile);
	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);


	return ss.str();
}



BOOL IsFileCanOpen(string filename)
{

	std::ifstream file(filename); 

	if (file.is_open()) {
		return TRUE;
		file.close(); 
	}
	else {
		return FALSE;
	}
}

LPSTR ConvertLPWSTRToLPSTR(LPWSTR lpwszStr) {
	LPSTR lpszStr = nullptr;
	int size = WideCharToMultiByte(CP_ACP, 0, lpwszStr, -1, nullptr, 0, nullptr, nullptr);
	if (size > 0) {
		lpszStr = new char[size];
		WideCharToMultiByte(CP_ACP, 0, lpwszStr, -1, lpszStr, size, nullptr, nullptr);
	}
	return lpszStr;
}

// 获取指定目录下的所有文件的完整路径名
vector<string> GetAllFilesInDirectory(const string& directoryPath) {
	vector<string> filePaths;
	WIN32_FIND_DATAA findFileData;
	HANDLE hFind = FindFirstFileA((directoryPath + "/*").c_str(), &findFileData);

	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			// 排除 . 和 .. 目录
			if (strcmp(findFileData.cFileName, ".") != 0 && strcmp(findFileData.cFileName, "..") != 0) {
				string filePath = directoryPath + "/" + findFileData.cFileName;
				filePaths.push_back(filePath);
			}
		} while (FindNextFileA(hFind, &findFileData) != 0);

		FindClose(hFind);
	}

	return filePaths;
}



BOOL ToScanFile(std::wstring parameters1, std::wstring parameters2,std::wstring programPath)
{

	//yara引擎不支持中文路径（Unicode）

	BOOL flag = FALSE;
	
	//STARTUPINFO si;
	//PROCESS_INFORMATION pi;
	//ZeroMemory(&si, sizeof(si));
	//si.cb = sizeof(si);
	//ZeroMemory(&pi, sizeof(pi));

	wchar_t buffer[MAX_PATH];
	GetModuleFileNameW(NULL, buffer, MAX_PATH);

	std::wstring modulePath(buffer);
	std::wstring::size_type pos = modulePath.find_last_of(L"\\");
	std::wstring currentDirectory = modulePath.substr(0, pos);


	std::wstring programPath2 = currentDirectory + L"\\" + programPath;
	std::wstring parametersp1 = parameters1.append(L" ");

	std::wstring parametersall = programPath2.append(L" ");

	parametersall = parametersall +L"\"" + parametersp1 +L"\"" + L"\"" + parameters2 + L"\"";

	

	
	LPWSTR lpProgramPath = const_cast<LPWSTR>(parametersall.c_str());

	wcout << "line:" << lpProgramPath << std::endl;

	//// 创建进程信息结构体
	//PROCESS_INFORMATION processInfo;
	//// 创建启动信息结构体
	//STARTUPINFO startupInfo;
	//// 初始化启动信息结构体
	//ZeroMemory(&startupInfo, sizeof(startupInfo));
	//startupInfo.cb = sizeof(startupInfo);

	//// 创建新进程
	//if (!CreateProcess(NULL,   // 模块名
	//	lpProgramPath,  // 命令行
	//	NULL,           // 进程安全描述符
	//	NULL,           // 线程安全描述符
	//	FALSE,          // 继承标志
	//	0,              // 创建标志
	//	NULL,           // 环境变量
	//	NULL,           // 当前目录
	//	&startupInfo,   // 启动信息结构体
	//	&processInfo)) // 进程信息结构体
	//{
	//	std::cerr << "CreateProcess failed: " << GetLastError() << std::endl;
	//	return ;
	//}

	//// 等待新进程结束
	//WaitForSingleObject(processInfo.hProcess, INFINITE);

	//// 关闭进程和线程句柄
	//CloseHandle(processInfo.hProcess);
	//CloseHandle(processInfo.hThread);


	   // 创建进程信息结构体
	PROCESS_INFORMATION processInfo;
	// 创建启动信息结构体
	STARTUPINFO startupInfo;
	// 初始化启动信息结构体
	ZeroMemory(&startupInfo, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);

	// 匿名管道句柄
	HANDLE hChildStdoutRead, hChildStdoutWrite;
	SECURITY_ATTRIBUTES saAttr;

	// 设置安全属性
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	// 创建管道
	if (!CreatePipe(&hChildStdoutRead, &hChildStdoutWrite, &saAttr, 0)) {
		std::cerr << "CreatePipe failed: " << GetLastError() << std::endl;
		return FALSE;
	}

	// 确保读取端的句柄不被继承
	if (!SetHandleInformation(hChildStdoutRead, HANDLE_FLAG_INHERIT, 0)) {
		std::cerr << "SetHandleInformation failed: " << GetLastError() << std::endl;
		return FALSE;
	}

	startupInfo.hStdError = hChildStdoutWrite;
	startupInfo.hStdOutput = hChildStdoutWrite;
	startupInfo.dwFlags |= STARTF_USESTDHANDLES;


	// 创建新进程
	if (!CreateProcess(NULL,   // 模块名
		ConvertLPWSTRToLPSTR(lpProgramPath),  // 命令行
		NULL,           // 进程安全描述符
		NULL,           // 线程安全描述符
		TRUE,          // 继承标志
		0,              // 创建标志
		NULL,           // 环境变量
		NULL,           // 当前目录
		&startupInfo,   // 启动信息结构体
		&processInfo)) // 进程信息结构体
	{
		std::cerr << "CreateProcess failed: " << GetLastError() << std::endl;
		return FALSE;
	}

	// 关闭写入端的句柄，因为父进程不需要写入
	CloseHandle(hChildStdoutWrite);

	// 读取子进程的输出
	DWORD dwRead;
	CHAR chBuf[4096];
	BOOL bSuccess = FALSE;
	std::string strOutput;

	while (true) {
		bSuccess = ReadFile(hChildStdoutRead, chBuf, 4096, &dwRead, NULL);
		if (!bSuccess || dwRead == 0) {
			break;
		}
		strOutput.append(chBuf, dwRead);
	}

	
	if (strOutput.find("error")!= std::string::npos)
	{
		flag = FALSE;
	}

	if (strOutput.find("error") == std::string::npos && strOutput.length()>0)
	{
		flag = TRUE;
	}

	// 打印子进程的输出
	std::cout << "Child process output: " << strOutput << std::endl;

	// 等待子进程结束
	WaitForSingleObject(processInfo.hProcess, INFINITE);

	// 关闭进程和线程句柄
	CloseHandle(processInfo.hProcess);
	CloseHandle(processInfo.hThread);
	CloseHandle(hChildStdoutRead);



	return flag;

}


bool createDirectory(const std::string& folderPath) {
	// 使用宽字符串路径创建文件夹
	if (CreateDirectoryA(folderPath.c_str(), NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
		return true;
	}
	else {
		std::cerr << "无法创建文件夹。错误代码: " << GetLastError() << std::endl;
		return false;
	}
}

void ReConnect(SOCKET talksocket, sockaddr_in saSrv)
{
	shutdown(talksocket, SD_BOTH);
	closesocket(talksocket);
	WSACleanup();
	int retcode = 0;
	do
	{

		WSAStartup(MAKEWORD(2, 2), &SockData);
		talksock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		saSrv.sin_addr.s_addr = inet_addr("192.168.1.2");
		saSrv.sin_family = AF_INET;
		saSrv.sin_port = htons(20156);
		retcode = connect(talksock, (sockaddr*)&saSrv, sizeof(saSrv));
		std::cout << "rec：" << retcode << "\n";
		if (retcode == 0)
		{
			break;
		}
		shutdown(talksocket, SD_BOTH);
		closesocket(talksocket);
		WSACleanup();
		Sleep(1000);
	} while (true);

}

void GetRemoteConmond()
{
	int retcode = 0;
	char CmdBuffer[512] = { 0 };
	do
	{
		retcode = recv(talksock, CmdBuffer, 8, 0);
		
		if (!retcode)
		{
			ReConnect(talksock, saSrv);
			ZeroMemory(CmdBuffer, 512);
			continue;
		}
		//心跳
		if (CmdBuffer[0] == 'A')
		{
			ZeroMemory(CmdBuffer, 512);
			continue;
		}
		//开日志
		if (CmdBuffer[0] == 'K')
		{
			g_bWriteLogFlag = TRUE;
			ZeroMemory(CmdBuffer, 512);
			continue;
		}
		//关日志
		if (CmdBuffer[0] == 'G')
		{
			g_bWriteLogFlag = FALSE;
			ZeroMemory(CmdBuffer, 512);
			continue;
		}


		/*for (size_t i = 0; i < 6; i++)
		{
			printf("%d ", CmdBuffer[i]);
		}
		printf("\n");*/

		if (CmdBuffer[7]==9)
		{
			//g_mtx.lock();

			g_UserRules.clear();

			if (CmdBuffer[0] == 1)
			{
				g_UserRules.push_back("webshells");
			}
			if (CmdBuffer[1] == 1)
			{
				g_UserRules.push_back("cve_rules");
			}
			if (CmdBuffer[2] == 1)
			{
				g_UserRules.push_back("crypto");
			}
			if (CmdBuffer[3] == 1)
			{
				g_UserRules.push_back("antidebug_antivm");
			}
			if (CmdBuffer[4] == 1)
			{
				g_UserRules.push_back("maldocs");
			}
			if (CmdBuffer[5] == 1)
			{
				g_UserRules.push_back("malware");
			}
			if (CmdBuffer[6] == 1)
			{
				g_UserRules.push_back("email");
			}

			//g_mtx.unlock();

			ZeroMemory(CmdBuffer, 512);
		}

	} while (1);
}


int main() {
	HANDLE hServerPort = nullptr;
	HANDLE hCompletion = nullptr;
	DWORD outSize = 0;
	ULONG_PTR key = 0;
	OVERLAPPED OverlappedGet = { 0 };
	GET_BUFF GetBufferStruct = { 0 };
	REPLY_STRUCT ReplyStruct = { 0 };
	PFILTER_MESSAGE_HEADER pFltMsg = nullptr;

	HANDLE hThread;
	DWORD dwThreadId;
	ProtectProcess((char*)to_string(GetCurrentProcessId()).c_str());


	int retcode = 0;
	WSAStartup(MAKEWORD(2, 2), &SockData);
	talksock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	saSrv.sin_addr.s_addr = inet_addr("192.168.1.2");
	saSrv.sin_family = AF_INET;
	saSrv.sin_port = htons(20156);
	retcode = connect(talksock, (sockaddr*)&saSrv, sizeof(saSrv));

	if (retcode < 0)
	{
		ReConnect(talksock, saSrv);
	}

	
	hThread = CreateThread(
		NULL,                   
		0,                    
		(LPTHREAD_START_ROUTINE)GetRemoteConmond,         
		NULL,         
		0,                      
		&dwThreadId            
	);


	wchar_t dirbuffer[MAX_PATH];
	GetModuleFileNameW(NULL, dirbuffer, MAX_PATH);

	std::wstring modulePath_1(dirbuffer);
	std::wstring::size_type pos_1 = modulePath_1.find_last_of(L"\\");
	std::wstring currentDirectory_1 = modulePath_1.substr(0, pos_1);
	currentDirectory_1.append(L"\\hptslogs");

	createDirectory(wstring2string(currentDirectory_1));
	//WaitForSingleObject(hThread,INFINITE);

	std::unordered_map<std::string, std::string> ScanResultData;
	std::unordered_map<std::string, std::string> WhiteData;

	pFltMsg = reinterpret_cast<PFILTER_MESSAGE_HEADER>(malloc(sizeof(FILTER_MESSAGE_HEADER) * 4));
	if (pFltMsg == nullptr) {
		throw runtime_error("Memory allocation failed!");
	}

	HRESULT hResult = FilterConnectCommunicationPort(
		L"\\ScannerPort",
		0,
		nullptr,
		0,
		nullptr,
		&hServerPort
	);

	if (hResult != S_OK) {
		MessageBoxA(nullptr, "Messager初始化失败! -Port", "ERRO", 0);
		return EXIT_FAILURE;
	}

	// 创建完成端口
	hCompletion = CreateIoCompletionPort(hServerPort, nullptr, 0, 1);
	if (hCompletion == nullptr) {
		MessageBoxA(nullptr, "Messager初始化失败! -ComPort", "ERRO", 0);
		return EXIT_FAILURE;
	}

	FilterGetMessage(hServerPort, reinterpret_cast<PFILTER_MESSAGE_HEADER>(&GetBufferStruct),
		sizeof(MY_STRUCTURE) + sizeof(FILTER_MESSAGE_HEADER), &OverlappedGet);

	BOOL IsVir = FALSE;

	do {
		if (GetQueuedCompletionStatus(hCompletion, &outSize, &key, reinterpret_cast<LPOVERLAPPED*>(&OverlappedGet), NULL)) {

			

			std::wstring FileName = wstring(ConvertToWide((char*)GetBufferStruct.Data.Filename));

			//wcout << "name:" << FileName << std::endl;

			ReplyStruct.Header.MessageId = GetBufferStruct.Header.MessageId;
			ReplyStruct.Header.Status = 0;
			//默认放行
			ReplyStruct.Flag = 0;

			if (
				(
					(FileName.find(L"Windows") == std::wstring::npos) && (FileName.find(L"Microsoft") == std::wstring::npos)
				) 
				&&
				(
					(FileName.find(L".exe") != std::wstring::npos) ||
					(FileName.find(L".dll") != std::wstring::npos) ||
					(FileName.find(L".sys") != std::wstring::npos) ||
					(FileName.find(L".txt") != std::wstring::npos) || 
					(FileName.find(L".jpg") != std::wstring::npos) || 
					(FileName.find(L".png") != std::wstring::npos) ||
					(FileName.find(L".bat") != std::wstring::npos) ||
					(FileName.find(L".ps")  != std::wstring::npos) 
			    )&&
				(
					(FileName.find(L"FileMessager") == std::wstring::npos) &&
					(FileName.find(L"RegFltMessager") == std::wstring::npos) &&
					(FileName.find(L"vm") == std::wstring::npos) && //过滤vm调试
					(FileName.find(L"VM") == std::wstring::npos) &&
					(FileName.find(L"explorer") == std::wstring::npos)&&
					(FileName.find(L"lass") == std::wstring::npos)&&
					(FileName.find(L"HPTS") == std::wstring::npos)
				)
			   )

			{

				if (IsFileCanOpen(std::string((const char*)(GetBufferStruct.Data.Filename))))
				{

					wchar_t buffer[MAX_PATH];
					GetModuleFileNameW(NULL, buffer, MAX_PATH);

					std::wstring modulePath(buffer);
					std::wstring::size_type pos = modulePath.find_last_of(L"\\");
					std::wstring currentDirectory = modulePath.substr(0, pos);

					//g_mtx.lock();
					for (size_t i = 0; i < g_UserRules.size(); i++)
					{
						string directoryPath = wstring2string(currentDirectory + L"\\" + ConvertToWide(g_UserRules[i].c_str()));

						vector<string> files = GetAllFilesInDirectory(directoryPath);

						// 打印所有文件的完整路径名
						for (const string& file : files) {
							IsVir = ToScanFile(ConvertToWide(file.c_str()), wstring(ConvertToWide((const char*)(GetBufferStruct.Data.Filename))), L"yara64.exe");
							if (IsVir)
							{
								goto VIRGOTHIS;
							}
						}
					}
					//g_mtx.unlock();
					
				}
				
			}
VIRGOTHIS:
			string logstr = getCurrentTime(TIME_FORMAT);
			if (g_bWriteLogFlag)
			{
				logstr = logstr +" " + (const char*)(GetBufferStruct.Data.Filename);
			}

			if (IsVir)
			{
				
				
				if (ScanResultData.find((char*)GetBufferStruct.Data.Filename) != ScanResultData.end())
				{
					if (!ScanResultData[(char*)GetBufferStruct.Data.Filename].compare(CalculateFileHash((char*)GetBufferStruct.Data.Filename)))
					{
						ReplyStruct.Flag = 99;
						goto DONTNEEDTIPLAB;
					}
				}

				if (WhiteData.find((char*)GetBufferStruct.Data.Filename) != WhiteData.end())
				{
					if (!WhiteData[(char*)GetBufferStruct.Data.Filename].compare(CalculateFileHash((char*)GetBufferStruct.Data.Filename)))
					{
						ReplyStruct.Flag = 0;
						goto DONTNEEDTIPLAB;
					}
				}

				

				std::string MsgWarn = "检测到\"";
				MsgWarn = MsgWarn + (char*)GetBufferStruct.Data.Filename;
				MsgWarn = MsgWarn + "\"文件有风险,是否放行?";

				int ChooseResult = MessageBoxA(NULL, MsgWarn.c_str(), "WARNING:拒绝或放行后改软件将会进入不受信列表,不再弹窗,直接拦截！", MB_OKCANCEL | MB_ICONWARNING);

				//printf("code：%d\n", ChooseResult);
				logstr = logstr + " unsafe";

				if (ChooseResult == 1)
				{
					printf("无毒\n");
					WhiteData[(char*)GetBufferStruct.Data.Filename] = CalculateFileHash((char*)GetBufferStruct.Data.Filename);
					ReplyStruct.Flag = 0;
					logstr = logstr + " user allow\n";
				}
				if(ChooseResult == 2)
				{
					//有毒 99 方便调试
					printf("有毒\n");
					ReplyStruct.Flag = 99;
					ScanResultData[(char*)GetBufferStruct.Data.Filename] = CalculateFileHash((char*)GetBufferStruct.Data.Filename);
					logstr = logstr + " user refuse\n";
				}
	
			}
			else
			{
				ReplyStruct.Flag = 0;
				logstr = logstr + " safe\n";
			}


			if (g_bWriteLogFlag)
			{
				appendToFile(logstr);
			}
DONTNEEDTIPLAB:
			IsVir = FALSE;

			FilterReplyMessage(hServerPort, reinterpret_cast<PFILTER_REPLY_HEADER>(&ReplyStruct),
				sizeof(REPLY_STRUCT));

			ZeroMemory(&GetBufferStruct, sizeof(GET_BUFF));

			FilterGetMessage(hServerPort, reinterpret_cast<PFILTER_MESSAGE_HEADER>(&GetBufferStruct),
				sizeof(MY_STRUCTURE) + sizeof(FILTER_MESSAGE_HEADER), &OverlappedGet);
		}
	} while (true);

	free(pFltMsg);

	return EXIT_SUCCESS;
}
