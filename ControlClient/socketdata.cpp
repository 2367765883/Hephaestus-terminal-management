#include "socketdata.h"
#include "tool.h"

_WINSOCK2API_::WSADATA SockData;
_WINSOCK2API_::SOCKET talksock;
_WINSOCK2API_::sockaddr_in saSrv;
_WINSOCK2API_::sockaddr_in saClt;


void InitSocket()
{
	ifstream inputfile("c:\\sk.config");
	string configip;
	getline(inputfile, configip);
	if (configip == "")
	{
		configip = "192.168.1.2";
	}

	int retcode = 0;
	WSAStartup(MAKEWORD(2, 2), &SockData);
	talksock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	saSrv.sin_addr.s_addr = inet_addr(configip.c_str());
	saSrv.sin_family = AF_INET;
	saSrv.sin_port = htons(19730);
	retcode = connect(talksock, (sockaddr*)&saSrv, sizeof(saSrv));
	if (retcode < 0)
	{
		ReConnect(talksock, saSrv);
	}
	std::cout << "overc：" << retcode << "\n";
	thread ToHeart(HeartBeat);
	thread GetCmd(GetRemoteConmond);
	ToHeart.join();
	GetCmd.join();
}
void SendData(char* buf, int datalen)
{
	send(talksock, buf, datalen, 0);
}
void HeartBeat()
{
	Json::CharReaderBuilder ReaderBuilder;
	ReaderBuilder["emitUTF8"] = true;
	Json::Value root;
	root["flag"] = "heart";
	root["name"] = GetSysName();
	root["time"] = GetSysTime();
	Json::StreamWriterBuilder writerBuilder;
	string jsonString = Json::writeString(writerBuilder, root);
	unsigned char* JsonChar = (unsigned char*)jsonString.c_str();
	//秘钥
	unsigned char key[] = SRC_KEY;
	int JsonCharLength = jsonString.length();
	int keyLength = strlen((char*)key);
	rc4Encrypt(JsonChar, JsonCharLength, key, keyLength);
	do
	{
		send(talksock, (char*)JsonChar, jsonString.length(), 0); Sleep(1000 * 60 * 2);
	} while (1);
}
void GetRemoteConmond()
{


	unsigned char key[] = SRC_KEY;
	int keyLength = strlen((char*)key);
	char CmdBuffer[4096] = { 0 };
	string stCmd;
	Json::Reader reader;
	Json::Value root;
	string flag = "";
	int retcode = 0;
	int datalen = 0;
	do
	{
		retcode = recv(talksock, CmdBuffer, 4096, 0);
		if (!retcode)
		{
			ReConnect(talksock, saSrv);
		}
		datalen = GetDataRelLenth(CmdBuffer, 4096);
		rc4Decrypt((unsigned char*)CmdBuffer, datalen, key, keyLength);
		SecondDecode(CmdBuffer, datalen);
		stCmd = CmdBuffer;
		reader.parse(stCmd, root);
		flag = root["flag"].asString();
		if (!flag.compare("GetProcesslist"))
		{
			Sleep(500);
			SendProcessList();
		}
		if (!flag.compare("kill"))
		{
			string type = root["type"].asString();
			string pid = root["pid"].asString();
			if (!type.compare("normal"))
			{
				NormalKillProcess((char*)pid.c_str());
			}
			if (!type.compare("strong"))
			{
				StrongKillProcess((char*)pid.c_str());
			}
		}
		if (!flag.compare("protect"))
		{
			string pid = root["pid"].asString();
			ProtectProcess((char*)pid.c_str());
		}
		if (!flag.compare("unprotect"))
		{
			string pid = root["pid"].asString();
			UnProtectProcess((char*)pid.c_str());
		}
		if (!flag.compare("getsys"))
		{
			string ip = root["ip"].asString();
			Sleep(1500);
			SendSysName(ip);
		}
		if (!flag.compare("dll-add"))
		{
			string DllName = root["name"].asString();
			AddDll((char*)DllName.c_str());


		}
		if (!flag.compare("dll-del"))
		{
			string DllName = root["name"].asString();
			DelDll((char*)DllName.c_str());


		}
		if (!flag.compare("initdir"))
		{
			InitDir();

		}
		if (!flag.compare("getdir"))
		{
			string dir = root["dir"].asString();
			QueryDir(dir);

		}
		if (!flag.compare("delfile"))
		{
			string name = root["name"].asString();
			DeleFiles(name);
		}
		if (!flag.compare("profile"))
		{
			string name = root["name"].asString();
			SetFileInaccessibleFalse((char*)name.c_str());
		}
		if (!flag.compare("unprofile"))
		{
			string name = root["name"].asString();
			SetFileInaccessibleTrue((char*)name.c_str());
		}
		if (!flag.compare("disabledebug"))
		{
			DisableDebug();
		}
		if (!flag.compare("enabledebug"))
		{
			EnableDebug();
		}
		if (!flag.compare("disanything"))
		{
			DisableAnything();
		}
		if (!flag.compare("enanything"))
		{
			EnableAnything();
		}
		if (!flag.compare("usb-off"))
		{
			DisableUsbToWrite();
		}
		if (!flag.compare("usb-on"))
		{
			EnableUsbToWrite();
		}
		if (!flag.compare("blackip"))
		{
			char* tmp = NULL;

			if (!root["ishost"].compare("1"))
			{
				tmp = GetIPAddress(root["ip"].asString().c_str());
			}
			else
			{
				tmp = (char*)root["ip"].asString().c_str();
			}

			BlockIP(tmp);

			
		}
		if (!flag.compare("removeip"))
		{
			char* tmp = NULL;
			tmp = GetIPAddress(root["ip"].asString().c_str());
			if (!strcmp(tmp,"N"))
			{
				RemoveBlacklistIP(root["ip"].asString().c_str());
			}
			else
			{
				RemoveBlacklistIP(tmp);
			}
			
		}
		stCmd = "";
		ZeroMemory(CmdBuffer, 512);

	} while (1);
}
string GetSysName()
{
	char computerName[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD size = sizeof(computerName);
	if (GetComputerName(computerName, &size)) {
		return string(computerName);
	}
	else {
		return string("");
	}
}
void SendProcessList()
{

	Json::Value root;
	root["flag"] = "process";
	Json::Value array(Json::arrayValue);
	int i = 0;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		// 处理错误
		return;
	}

	// 获取进程列表
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnapshot, &pe32))
	{

		do
		{
			// 获取进程ID
			DWORD dwProcessId = pe32.th32ProcessID;
			// 获取进程路径
			TCHAR szProcessPath[260] = { 0 };
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessId);
			if (hProcess)
			{

				DWORD dwSize = MAX_PATH;
				if (QueryFullProcessImageName(hProcess, 0, szProcessPath, &dwSize))
				{

					Json::Value obj;
					obj["name"] = pe32.szExeFile;
					obj["pid"] = to_string(dwProcessId);
					obj["path"] = string(szProcessPath);
					array.append(obj);
				}
				CloseHandle(hProcess);
			}
			i++;
			// 获取下一个进程
		} while (Process32Next(hSnapshot, &pe32));
	}
	root["array"] = array;
	Json::StreamWriterBuilder writer;
	std::string jsonString = Json::writeString(writer, root);
	unsigned char* JsonChar = (unsigned char*)jsonString.c_str();
	//秘钥
	unsigned char key[] = SRC_KEY;
	int JsonCharLength = jsonString.length();
	int keyLength = strlen((char*)key);
	rc4Encrypt(JsonChar, JsonCharLength, key, keyLength);
	send(talksock, (char*)JsonChar, jsonString.length(), 0);
	CloseHandle(hSnapshot);
}
string GetSysTime()
{
	time_t currentTime = std::time(nullptr);
	tm* localTime = std::localtime(&currentTime);
	int year = localTime->tm_year + 1900;
	int month = localTime->tm_mon + 1;
	int day = localTime->tm_mday;
	int hour = localTime->tm_hour;
	int minute = localTime->tm_min;
	int second = localTime->tm_sec;
	return to_string(year)
		+ "-"
		+ to_string(month)
		+ "-"
		+ to_string(day)
		+ to_string(hour)
		+ to_string(minute);
}
void NormalKillProcess(char* pids)
{
	DWORD pid = stoi(pids);
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (hProcess == NULL) {
		return;
	}
	if (!TerminateProcess(hProcess, 0)) {
		return;
	}
	CloseHandle(hProcess);
}
void StrongKillProcess(char* pids)
{
	HANDLE hDevice = NULL;
	DWORD retlen = NULL;
	hDevice = CreateFile(SYMBOLIC_NAME, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DeviceIoControl(hDevice, CTL_KILL, pids, strlen(pids), NULL, 0, &retlen, NULL);
	CloseHandle(hDevice);
}
void ProtectProcess(char* pids)
{
	HANDLE hDevice = NULL;
	DWORD retlen = NULL;
	hDevice = CreateFile(SYMBOLIC_NAME, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DeviceIoControl(hDevice, CTL_PROT, pids, strlen(pids), NULL, 0, &retlen, NULL);
	CloseHandle(hDevice);
}
void UnProtectProcess(char* pids)
{
	HANDLE hDevice = NULL;
	DWORD retlen = NULL;
	hDevice = CreateFile(SYMBOLIC_NAME, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DeviceIoControl(hDevice, CTL_UNPROT, pids, strlen(pids), NULL, 0, &retlen, NULL);
	CloseHandle(hDevice);
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
		saSrv.sin_port = htons(19730);
		retcode = connect(talksock, (sockaddr*)&saSrv, sizeof(saSrv));
		std::cout <<"rec：" << retcode << "\n";
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
void SendSysName(string ip)
{
	Json::CharReaderBuilder ReaderBuilder;
	ReaderBuilder["emitUTF8"] = true;
	Json::Value root;
	root["flag"] = "sysname";
	root["ip"] = ip;
	root["data"] = GetSysName();
	Json::StreamWriterBuilder writerBuilder;
	string jsonString = Json::writeString(writerBuilder, root);
	unsigned char* JsonChar = (unsigned char*)jsonString.c_str();
	//秘钥
	unsigned char key[] = SRC_KEY;
	int JsonCharLength = jsonString.length();
	int keyLength = strlen((char*)key);
	rc4Encrypt(JsonChar, JsonCharLength, key, keyLength);
	send(talksock, (char*)JsonChar, jsonString.length(), 0);

}
void RC4DecryptForString(const std::string& key, std::string& data) {
	int state[256];
	int keyLength = key.size();

	for (int i = 0; i < 256; ++i) {
		state[i] = i;
	}

	int j = 0;
	for (int i = 0; i < 256; ++i) {
		j = (j + state[i] + key[i % keyLength]) % 256;
		std::swap(state[i], state[j]);
	}

	int i = 0;
	j = 0;
	int dataLength = data.size();

	for (int k = 0; k < dataLength; ++k) {
		i = (i + 1) % 256;
		j = (j + state[i]) % 256;

		std::swap(state[i], state[j]);
		int t = (state[i] + state[j]) % 256;

		data[k] ^= state[t];
	}
}
std::string base64Decode(const std::string& encoded) {
	std::string base64Chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	unsigned char decodingTable[256] = { 0 };

	for (int i = 0; i < 64; ++i) {
		decodingTable[base64Chars[i]] = i;
	}

	std::string decoded;
	int i = 0;
	int len = encoded.length();
	int padding = 0;

	while (i < len && encoded[i] != '=') {
		unsigned char b0 = decodingTable[encoded[i++]];
		unsigned char b1 = decodingTable[encoded[i++]];
		unsigned char b2 = decodingTable[encoded[i++]];
		unsigned char b3 = decodingTable[encoded[i++]];

		unsigned char ch1 = (b0 << 2) | (b1 >> 4);
		unsigned char ch2 = (b1 << 4) | (b2 >> 2);
		unsigned char ch3 = (b2 << 6) | b3;

		decoded += ch1;
		decoded += ch2;
		decoded += ch3;
	}

	if (i < len && encoded[i] == '=') {
		++padding;
		if (i + 1 < len && encoded[i + 1] == '=') {
			++padding;
		}
	}

	decoded.resize(decoded.size() - padding);
	return decoded;
}
int GetDataRelLenth(char* buf, int length)
{
	int rellen = 0;
	for (size_t i = 0; i < length; i++)
	{
		if (buf[i] != 0)
		{
			rellen = i + 1;
		}
	}
	return rellen;
}
void SecondDecode(char* buf, int length)
{
	int rellen = 0;
	for (size_t i = 0; i < length; i++)
	{
		if (buf[i] != 0)
		{
			rellen = i + 1;
		}
		buf[i] = buf[i] - 39;
	}
}
void AddDll(char* name)
{
	HANDLE hDevice = NULL;
	DWORD retlen = NULL;
	hDevice = CreateFile(SYMBOLIC_NAME, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DeviceIoControl(hDevice, CTL_ADDDLL, name, strlen(name), NULL, 0, &retlen, NULL);
	CloseHandle(hDevice);
}
void DelDll(char* name)
{
	HANDLE hDevice = NULL;
	DWORD retlen = NULL;
	hDevice = CreateFile(SYMBOLIC_NAME, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DeviceIoControl(hDevice, CTL_DELDLL, name, strlen(name), NULL, 0, &retlen, NULL);
	CloseHandle(hDevice);
}
void InitDir()
{
	Json::Value root;
	root["flag"] = "dirinitdata";
	Json::Value array(Json::arrayValue);
	char buffer[MAX_PATH];
	DWORD drives = GetLogicalDrives();
	for (int i = 0; i < 26; ++i) {
		if ((drives & (1 << i)) != 0) {
			char driveLetter[] = { static_cast<char>('A' + i), ':', '\\', '\0' };
			if (GetDriveType(driveLetter) == DRIVE_FIXED) {
				if (GetVolumeInformation(driveLetter, buffer, sizeof(buffer), nullptr, nullptr, nullptr, nullptr, 0)) {

					Json::Value obj;
					obj["dir"] = driveLetter;
					obj["labelname"] = base64Encode((const unsigned char*)buffer, strlen(buffer));;
					array.append(obj);
				}
				else {
					Json::Value obj;
					obj["dir"] = driveLetter;
					obj["labelname"] = "NULL";
					array.append(obj);
				}
			}
		}
	}
	root["array"] = array;
	Json::StreamWriterBuilder writer;
	std::string jsonString = Json::writeString(writer, root);
	unsigned char* JsonChar = (unsigned char*)jsonString.c_str();
	//秘钥
	unsigned char key[] = SRC_KEY;
	int JsonCharLength = jsonString.length();
	int keyLength = strlen((char*)key);
	rc4Encrypt(JsonChar, JsonCharLength, key, keyLength);
	Sleep(500);
	send(talksock, (char*)JsonChar, jsonString.length(), 0);

}
void QueryDir(const std::string& folderPath)
{
	Json::Value root;
	root["flag"] = "querydir";
	Json::Value array(Json::arrayValue);
	string searchPath = folderPath + "\\*";
	WIN32_FIND_DATAA findData;
	HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
	if (hFind != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0)
				{
					Json::Value obj;
					obj["dir"] = base64Encode((const unsigned char*)findData.cFileName, strlen(findData.cFileName));
					obj["attributes"] = "folder";
					array.append(obj);
				}
			}
			else
			{
				Json::Value obj;
				obj["dir"] = base64Encode((const unsigned char*)findData.cFileName, strlen(findData.cFileName));
				obj["attributes"] = "file";
				array.append(obj);
			}
		} while (FindNextFileA(hFind, &findData));

		FindClose(hFind);
	}
	root["array"] = array;
	Json::StreamWriterBuilder writer;
	std::string jsonString = Json::writeString(writer, root);
	unsigned char* JsonChar = (unsigned char*)jsonString.c_str();
	//秘钥
	unsigned char key[] = SRC_KEY;
	int JsonCharLength = jsonString.length();
	int keyLength = strlen((char*)key);
	rc4Encrypt(JsonChar, JsonCharLength, key, keyLength);
	Sleep(500);
	send(talksock, (char*)JsonChar, jsonString.length(), 0);
}
void DeleFiles(string name)
{
	char* names = (char*)name.c_str();
	HANDLE hDevice = NULL;
	DWORD retlen = NULL;
	hDevice = CreateFile(SYMBOLIC_NAME, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DeviceIoControl(hDevice, CTL_DELFILE, names, strlen(names), NULL, 0, &retlen, NULL);
	CloseHandle(hDevice);
}
bool SetFileInaccessibleFalse(char* names)
{
	HANDLE hDevice = NULL;
	DWORD retlen = NULL;
	hDevice = CreateFile(SYMBOLIC_NAME, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	cout << hDevice << endl;
	DeviceIoControl(hDevice, CTL_ADDFILE, names, strlen(names), NULL, 0, &retlen, NULL);
	cout << GetLastError() << endl;
	CloseHandle(hDevice);
	return true;
}
bool SetFileInaccessibleTrue(char* names)
{
	HANDLE hDevice = NULL;
	DWORD retlen = NULL;
	hDevice = CreateFile(SYMBOLIC_NAME, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	cout << hDevice << endl;
	DeviceIoControl(hDevice, CTL_DELFILENAME, names, strlen(names), NULL, 0, &retlen, NULL);
	cout << GetLastError() << endl;
	CloseHandle(hDevice);
	return true;
}
void DisableDebug()
{
	char buf[1] = { 0 };
	HANDLE hDevice = NULL;
	DWORD retlen = NULL;
	hDevice = CreateFile(SYMBOLIC_NAME, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DeviceIoControl(hDevice, CTL_DISABLE_DEBUG, buf, strlen(buf), NULL, 0, &retlen, NULL);
	CloseHandle(hDevice);
}
void EnableDebug()
{
	char buf[1] = { 0 };
	HANDLE hDevice = NULL;
	DWORD retlen = NULL;
	hDevice = CreateFile(SYMBOLIC_NAME, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DeviceIoControl(hDevice, CTL_ENABLE_DEBUG, buf, strlen(buf), NULL, 0, &retlen, NULL);
	CloseHandle(hDevice);
}
void DisableAnything()
{
	
	HANDLE hDevice = NULL;
	DWORD retlen = NULL;
	hDevice = CreateFileA(MOUSYM_NAME, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	printf("err：%d\n", GetLastError());
	DeviceIoControl(hDevice, CTL_START_MOUFLT, NULL, NULL, NULL, 0, &retlen, NULL);
	CloseHandle(hDevice);
}
void EnableAnything()
{
	HANDLE hDevice = NULL;
	DWORD retlen = NULL;
	hDevice = CreateFileA(MOUSYM_NAME, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	printf("err：%d\n", GetLastError());
	DeviceIoControl(hDevice, CTL_STOP_MOUFLT, NULL, NULL, NULL, 0, &retlen, NULL);
	CloseHandle(hDevice);
}
void DisableUsbToWrite()
{
	HANDLE hDevice = NULL;
	DWORD retlen = NULL;
	hDevice = CreateFileA(WPDSYM_NAME, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	printf("err：%d\n", GetLastError());
	DeviceIoControl(hDevice, CTL_START_WPDFLT, NULL, NULL, NULL, 0, &retlen, NULL);
	CloseHandle(hDevice);

}
void EnableUsbToWrite()
{
	HANDLE hDevice = NULL;
	DWORD retlen = NULL;
	hDevice = CreateFile(WPDSYM_NAME, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DeviceIoControl(hDevice, CTL_STOP_WPDFLT, NULL, NULL, NULL, 0, &retlen, NULL);
	CloseHandle(hDevice);
}
bool BlockIP(const char* ip)
{
	HANDLE hDevice = NULL;
	DWORD retlen = NULL;
	hDevice = CreateFile(WPDSYM_NAME, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DeviceIoControl(hDevice, CTL_STOP_WPDFLT, (LPVOID)ip, strlen(ip), NULL, 0, &retlen, NULL);
	CloseHandle(hDevice);
	return true;
}


bool RemoveBlacklistIP(const char* ip) {
	HANDLE hDevice = NULL;
	DWORD retlen = NULL;
	hDevice = CreateFile(NETSYM_NAME, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DeviceIoControl(hDevice, CTL_REMOVEBLOCK, (LPVOID)ip, strlen(ip), NULL, 0, &retlen, NULL);
	CloseHandle(hDevice);
	return true;
}