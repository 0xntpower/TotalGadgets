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

#include <shellapi.h>

#include <cstdio>
#include <io.h>
#include <iostream>

#include "Cli.hpp"
#include "MainDlg.hpp"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "advapi32.lib")

namespace {

bool HasCliArgs() {
    int argc = 0;
    LPWSTR* argv = ::CommandLineToArgvW(::GetCommandLineW(), &argc);
    if (!argv)
        return false;
    bool cli = argc > 1;
    ::LocalFree(argv);
    return cli;
}

// GUI-subsystem exe: when launched from a console, attach to it so CLI mode
// can print. If stdout is already redirected to a pipe/file, leave it alone.
void AttachToParentConsole() {
    const HANDLE out = ::GetStdHandle(STD_OUTPUT_HANDLE);
    const bool redirected = out != nullptr && out != INVALID_HANDLE_VALUE;

    if (!redirected && ::AttachConsole(ATTACH_PARENT_PROCESS)) {
        FILE* f = nullptr;
        freopen_s(&f, "CONOUT$", "w", stdout);
        freopen_s(&f, "CONOUT$", "w", stderr);
        freopen_s(&f, "CONIN$", "r", stdin);
        std::cout.clear();
        std::cerr.clear();
        std::cin.clear();
    }
}

} // namespace

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    if (HasCliArgs()) {
        AttachToParentConsole();
        int argc = 0;
        LPWSTR* argv = ::CommandLineToArgvW(::GetCommandLineW(), &argc);
        const int rc = gadgets::CliMain(argc, argv);
        if (argv)
            ::LocalFree(argv);
        return rc;
    }

    ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    INITCOMMONCONTROLSEX icc = { sizeof(icc),
                                 ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES |
                                     ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES |
                                     ICC_TAB_CLASSES };
    ::InitCommonControlsEx(&icc);

    _Module.Init(nullptr, hInstance);
    CMessageLoop loop;
    _Module.AddMessageLoop(&loop);

    // Modeless main window: our own pump lets menu accelerators (F5,
    // Ctrl+1/2, Ctrl+E) translate, which the modal DialogBox loop cannot.
    gadgets::MainDlg dlg;
    dlg.Create(nullptr);
    dlg.ShowWindow(SW_SHOW);

    const HACCEL hAccel =
        ::LoadAcceleratorsW(hInstance, MAKEINTRESOURCEW(IDR_ACCEL));

    MSG msg;
    for (;;) {
        const BOOL bRet = ::GetMessageW(&msg, nullptr, 0, 0);
        if (bRet == 0 || bRet == -1)
            break;
        // Only keyboard messages need dialog-manager navigation; routing
        // everything through IsDialogMessage lets it swallow non-input
        // messages (WM_TIMER et al.) that it claims to "process".
        if (msg.message >= WM_KEYFIRST && msg.message <= WM_KEYLAST &&
            ::IsDialogMessageW(dlg, &msg))
            continue;
        ::TranslateMessage(&msg);
        ::DispatchMessageW(&msg);
    }

    if (dlg.IsWindow())
        dlg.DestroyWindow();

    _Module.RemoveMessageLoop();

    _Module.Term();
    ::CoUninitialize();

    return 0;
}
