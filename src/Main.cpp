#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <commctrl.h>

#include <atlbase.h>
#include <atlapp.h>

CAppModule _Module;

#include <atlwin.h>

#include "MainDlg.hpp"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "advapi32.lib")


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES };
    ::InitCommonControlsEx(&icc);

    _Module.Init(nullptr, hInstance);

    gadgets::MainDlg dlg;
    dlg.DoModal();

    _Module.Term();
    ::CoUninitialize();
    return 0;
}
