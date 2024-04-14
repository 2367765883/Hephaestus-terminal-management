
#include "socketdata.h"
#include "tool.h"
//#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" ) 




int main(int argc, char** argv)
{
	InitSelf();
	InitSocket();
	return 0;
}
