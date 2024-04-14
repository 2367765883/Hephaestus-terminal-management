
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
#include <tlhelp32.h>
#include <tchar.h>
#include <vector>

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

#define  BUFFER_SIZE 1024

#pragma comment(lib, "FltLib.lib")



using namespace std;

// �����ں˲㷢�͹������ļ����
typedef struct _MY_STRUCTURE {
	WCHAR RegPath[512];
	ULONG uPid;
} MY_STRUCTURE;

// Ӧ�ò㷢�����ݵĽṹ��
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

	wchar_t* wideStr = new wchar_t[length + 1]; // �����㹻�Ŀռ�
	mbstowcs(wideStr, narrowStr, length + 1);

	return wideStr;
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


BOOL GetProcessNameByPID(DWORD dwPID, char* szProcessName)
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	BOOL bFound = FALSE;

	// ��ȡ���̿���
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	// ��ʼ���ṹ��
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// ��ȡ��һ�����̵���Ϣ
	if (!Process32First(hSnapshot, &pe32))
	{
		CloseHandle(hSnapshot);
		return FALSE;
	}

	// �������н���
	do
	{
		if (pe32.th32ProcessID == dwPID)
		{
			strncpy(szProcessName, pe32.szExeFile, strlen(pe32.szExeFile));
			bFound = TRUE;
			break;
		}
	} while (Process32Next(hSnapshot, &pe32));

	CloseHandle(hSnapshot);
	return bFound;
}


BOOL ToScanFile(std::wstring parameters1, std::wstring parameters2, std::wstring programPath)
{

	//yara���治֧������·����Unicode��

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
	std::wstring parametersp1 = currentDirectory + L"\\" + parameters1;

	std::wstring parametersall = programPath2.append(L" ");

	parametersall = parametersall + parametersp1 + L"\"" + parameters2 + L"\"";




	LPWSTR lpProgramPath = const_cast<LPWSTR>(parametersall.c_str());

	wcout << "line:" << lpProgramPath << std::endl;

	//// ����������Ϣ�ṹ��
	//PROCESS_INFORMATION processInfo;
	//// ����������Ϣ�ṹ��
	//STARTUPINFO startupInfo;
	//// ��ʼ��������Ϣ�ṹ��
	//ZeroMemory(&startupInfo, sizeof(startupInfo));
	//startupInfo.cb = sizeof(startupInfo);

	//// �����½���
	//if (!CreateProcess(NULL,   // ģ����
	//	lpProgramPath,  // ������
	//	NULL,           // ���̰�ȫ������
	//	NULL,           // �̰߳�ȫ������
	//	FALSE,          // �̳б�־
	//	0,              // ������־
	//	NULL,           // ��������
	//	NULL,           // ��ǰĿ¼
	//	&startupInfo,   // ������Ϣ�ṹ��
	//	&processInfo)) // ������Ϣ�ṹ��
	//{
	//	std::cerr << "CreateProcess failed: " << GetLastError() << std::endl;
	//	return ;
	//}

	//// �ȴ��½��̽���
	//WaitForSingleObject(processInfo.hProcess, INFINITE);

	//// �رս��̺��߳̾��
	//CloseHandle(processInfo.hProcess);
	//CloseHandle(processInfo.hThread);


	   // ����������Ϣ�ṹ��
	PROCESS_INFORMATION processInfo;
	// ����������Ϣ�ṹ��
	STARTUPINFO startupInfo;
	// ��ʼ��������Ϣ�ṹ��
	ZeroMemory(&startupInfo, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);

	// �����ܵ����
	HANDLE hChildStdoutRead, hChildStdoutWrite;
	SECURITY_ATTRIBUTES saAttr;

	// ���ð�ȫ����
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	// �����ܵ�
	if (!CreatePipe(&hChildStdoutRead, &hChildStdoutWrite, &saAttr, 0)) {
		std::cerr << "CreatePipe failed: " << GetLastError() << std::endl;
		return FALSE;
	}

	// ȷ����ȡ�˵ľ�������̳�
	if (!SetHandleInformation(hChildStdoutRead, HANDLE_FLAG_INHERIT, 0)) {
		std::cerr << "SetHandleInformation failed: " << GetLastError() << std::endl;
		return FALSE;
	}

	startupInfo.hStdError = hChildStdoutWrite;
	startupInfo.hStdOutput = hChildStdoutWrite;
	startupInfo.dwFlags |= STARTF_USESTDHANDLES;

	// �����½���
	if (!CreateProcess(NULL,   // ģ����
		ConvertLPWSTRToLPSTR(lpProgramPath),  // ������
		NULL,           // ���̰�ȫ������
		NULL,           // �̰߳�ȫ������
		TRUE,          // �̳б�־
		0,              // ������־
		NULL,           // ��������
		NULL,           // ��ǰĿ¼
		&startupInfo,   // ������Ϣ�ṹ��
		&processInfo)) // ������Ϣ�ṹ��
	{
		std::cerr << "CreateProcess failed: " << GetLastError() << std::endl;
		return FALSE;
	}

	// �ر�д��˵ľ������Ϊ�����̲���Ҫд��
	CloseHandle(hChildStdoutWrite);

	// ��ȡ�ӽ��̵����
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


	if (strOutput.find("error") != std::string::npos)
	{
		flag = FALSE;
	}

	if (strOutput.find("error") == std::string::npos && strOutput.length() > 0)
	{
		flag = TRUE;
	}

	// ��ӡ�ӽ��̵����
	std::cout << "Child process output: " << strOutput << std::endl;

	// �ȴ��ӽ��̽���
	WaitForSingleObject(processInfo.hProcess, INFINITE);

	// �رս��̺��߳̾��
	CloseHandle(processInfo.hProcess);
	CloseHandle(processInfo.hThread);
	CloseHandle(hChildStdoutRead);



	return flag;

}


char* WideCharToMultiByteString(const wchar_t* wideCharString)
{
	int bufferSize = WideCharToMultiByte(CP_UTF8, 0, wideCharString, -1, NULL, 0, NULL, NULL);
	if (bufferSize == 0) {
		std::cerr << "WideCharToMultiByte failed with error: " << GetLastError() << std::endl;
		return nullptr;
	}

	std::vector<char> buffer(bufferSize);
	if (WideCharToMultiByte(CP_UTF8, 0, wideCharString, -1, buffer.data(), bufferSize, NULL, NULL) == 0) {
		std::cerr << "WideCharToMultiByte failed with error: " << GetLastError() << std::endl;
		return nullptr;
	}

	char* multiByteString = new char[bufferSize];
	strncpy(multiByteString, buffer.data(), bufferSize);
	return multiByteString;
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

	ProtectProcess((char*)to_string(GetCurrentProcessId()).c_str());

	std::unordered_map<std::string, std::string> ScanResultData;

	pFltMsg = reinterpret_cast<PFILTER_MESSAGE_HEADER>(malloc(sizeof(FILTER_MESSAGE_HEADER) * 4));
	if (pFltMsg == nullptr) {
		throw runtime_error("Memory allocation failed!");
	}

	HRESULT hResult = FilterConnectCommunicationPort(
		L"\\RegPort",
		0,
		nullptr,
		0,
		nullptr,
		&hServerPort
	);

	if (hResult != S_OK) {
		MessageBoxA(nullptr, "Messager��ʼ��ʧ��! -Port", "ERRO", 0);
		return EXIT_FAILURE;
	}

	// ������ɶ˿�
	hCompletion = CreateIoCompletionPort(hServerPort, nullptr, 0, 1);
	if (hCompletion == nullptr) {
		MessageBoxA(nullptr, "Messager��ʼ��ʧ��! -ComPort", "ERRO", 0);
		return EXIT_FAILURE;
	}

	FilterGetMessage(hServerPort, reinterpret_cast<PFILTER_MESSAGE_HEADER>(&GetBufferStruct),
		sizeof(MY_STRUCTURE) + sizeof(FILTER_MESSAGE_HEADER), &OverlappedGet);

	BOOL IsVir = FALSE;

	do {
		if (GetQueuedCompletionStatus(hCompletion, &outSize, &key, reinterpret_cast<LPOVERLAPPED*>(&OverlappedGet), NULL)) {



			WCHAR* wchRegpath = GetBufferStruct.Data.RegPath;
			ULONG uOprPid = GetBufferStruct.Data.uPid;

			char szOprProcessName[260] = { 0 };
			//wcout << "name:" << FileName << std::endl;

			GetProcessNameByPID(uOprPid, szOprProcessName);

			wstring FileName(ConvertToWide(szOprProcessName));

			ReplyStruct.Header.MessageId = GetBufferStruct.Header.MessageId;
			ReplyStruct.Header.Status = 0;

			//Ĭ�Ϸ���
			ReplyStruct.Flag = 0;

			if (
				
				(
					(FileName.find(L"conhost") != std::wstring::npos) ||
					(FileName.find(L"csrss") != std::wstring::npos) ||
					(FileName.find(L"ctfmon") != std::wstring::npos) ||
					(FileName.find(L"winlogon") != std::wstring::npos) ||
					(FileName.find(L"dwm") != std::wstring::npos) ||
					(FileName.find(L"dllhost") != std::wstring::npos)
					)
				)

			{

				/*if (IsFileCanOpen(std::string(szOprProcessName)))
				{
					IsVir = ToScanFile(std::wstring(L"demorulec.yara "), FileName, L"yara64_2.exe");
				}*/

				IsVir = TRUE;

			}

			if (IsVir)
			{


				/*	if (ScanResultData.find((char*)GetBufferStruct.Data.Filename) != ScanResultData.end())
					{
						if (!ScanResultData[(char*)GetBufferStruct.Data.Filename].compare(CalculateFileHash((char*)GetBufferStruct.Data.Filename)))
						{
							ReplyStruct.Flag = 99;
							goto DONTNEEDTIPLAB;
						}
					}

					ScanResultData[(char*)GetBufferStruct.Data.Filename] = CalculateFileHash((char*)GetBufferStruct.Data.Filename);*/

				std::string MsgWarn = "��⵽\"";
				MsgWarn = MsgWarn + szOprProcessName;
				MsgWarn = MsgWarn + "\"�ļ����в���ע������,�Ƿ����?\n";
				MsgWarn = MsgWarn +"����ע���·��:" + WideCharToMultiByteString(wchRegpath);

				int ChooseResult = MessageBoxA(NULL, MsgWarn.c_str(), "WARNING��", MB_OKCANCEL | MB_ICONWARNING);

				//printf("code��%d\n", ChooseResult);

				if (ChooseResult == 1)
				{
					ReplyStruct.Flag = 0;
				}
				if (ChooseResult == 2)
				{
					//�ж� 99 �������
					ReplyStruct.Flag = 99;
				}

			}
			else
			{
				ReplyStruct.Flag = 0;
			}

		DONTNEEDTIPLAB:
			IsVir = FALSE;

			printf("%d\n", ReplyStruct.Flag);

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
