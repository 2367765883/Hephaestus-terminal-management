#pragma once

const PWSTR MESSAGE_PORT_NAME = L"\\RegPort";

typedef enum { READ, WRITE, DEL, OTHER } MESSAGE_TYPE;
typedef struct {
	WCHAR Regpath[512];
	ULONG uPid;
} MESSAGE_REQ, * PMESSAGE_REQ;

typedef struct {
	CHAR IsSafe;
} MESSAGE_REPLY, * PMESSAGE_REPLY;

