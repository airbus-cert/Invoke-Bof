#include <windows.h>
#include "beacon.h"
#define AUTHOR_METADATA                                L"\t***********\n\tAirbus CERT\n\t***********"

DECLSPEC_IMPORT HWND WINAPI USER32$GetForegroundWindow();
DECLSPEC_IMPORT int WINAPI USER32$GetWindowTextA(HWND, LPSTR *, int);
DECLSPEC_IMPORT BOOL WINAPI USER32$OpenClipboard(HWND);
DECLSPEC_IMPORT HANDLE WINAPI USER32$GetClipboardData(UINT);
DECLSPEC_IMPORT BOOL WINAPI USER32$CloseClipboard();

// For debug purpose
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$DebugBreak();

void go(char *args, int len) {
    datap parser;
	formatp format;
	int argSz;
	DWORD arg2;

    BeaconDataParse(&parser, args, len);
	char* arg1 = BeaconDataExtract(&parser, &argSz);
	arg2 = BeaconDataInt(&parser);

	//KERNEL32$DebugBreak();
	
    BeaconPrintf(CALLBACK_OUTPUT, "%ls\n", (wchar_t*)AUTHOR_METADATA);
	BeaconPrintf(CALLBACK_OUTPUT, "%s\n", "Test Beacon for Invoke-Bof");
	BeaconPrintf(CALLBACK_OUTPUT, "Argument 1 : %s\n", arg1);
	BeaconPrintf(CALLBACK_OUTPUT, "Argument 2 : %d\n", arg2);
	
	BeaconFormatAlloc(&format, 0x1000);
	BeaconFormatReset(&format);
	BeaconFormatAppend(&format, "foo", 4);
	BeaconFormatInt(&format, 111);
	
	BeaconFormatPrintf(&format, "%s %d", "bar", 222);
	BeaconFormatPrintf(&format, "%d", 333);
	
	int bufferSz = 0;
	char* buffer = BeaconFormatToString(&format, &bufferSz);
	
	BeaconOutput(CALLBACK_OUTPUT, buffer, bufferSz);
	BeaconFormatFree(&format);
	
	wchar_t test_convert[100];
	toWideChar("foo", test_convert, 100);
	BeaconPrintf(CALLBACK_ERROR, "\nTEST toWideChar %ls\n", test_convert);

    if (BeaconIsAdmin()) {
        BeaconPrintf(CALLBACK_ERROR, "You are Admin!\n");
    }
	else
	{
		BeaconPrintf(CALLBACK_ERROR, "You NOT are Admin!\n");
	}
	
	LPSTR windowsName[250];
    int maxSizeName = 250;
    HWND foreground = USER32$GetForegroundWindow();
    USER32$GetWindowTextA(foreground, windowsName, maxSizeName);

    if (USER32$OpenClipboard(NULL))
	{
		HANDLE h = USER32$GetClipboardData(CF_TEXT);

		BeaconPrintf(CALLBACK_OUTPUT, "[+] Clipboard updated !\n[!] Active Windows : %s\n[!] Content : %s\n----------------------------------\n", windowsName, (char*)h);
		USER32$CloseClipboard();
	}
}