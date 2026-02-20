#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>

#include <atlbase.h>
#include <atlapp.h>

extern CAppModule _Module;

#include <atlwin.h>
#include <atlcrack.h>
#include <atlctrls.h>
#include <atldlgs.h>
#include <atlframe.h>
#include <atlmisc.h>

#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include <librp.hpp>

#include "Resource.h"
#include "Scanner.hpp"

namespace gadgets {

constexpr UINT WM_SCAN_LOG = WM_APP + 1;
constexpr UINT WM_SCAN_PROGRESS = WM_APP + 2;
constexpr UINT WM_SCAN_DONE = WM_APP + 3;
constexpr UINT_PTR kTimerId = 1;

class MainDlg : public CDialogImpl<MainDlg>, public CDialogResize<MainDlg> {
public:
    enum { IDD = IDD_MAINDLG };

    BEGIN_MSG_MAP(MainDlg)
        MSG_WM_INITDIALOG(OnInitDialog)
        MSG_WM_DESTROY(OnDestroy)
        MSG_WM_TIMER(OnTimer)
        MSG_WM_GETMINMAXINFO(OnGetMinMaxInfo)
        COMMAND_ID_HANDLER_EX(IDC_BROWSE_FOLDER, OnBrowseFolder)
        COMMAND_ID_HANDLER_EX(IDC_BROWSE_OUTPUT, OnBrowseOutput)
        COMMAND_ID_HANDLER_EX(IDC_SCAN, OnScan)
        COMMAND_ID_HANDLER_EX(IDC_ENABLE_MUTATION, OnToggleMutation)
        COMMAND_ID_HANDLER_EX(IDCANCEL, OnCancel)
        MESSAGE_HANDLER_EX(WM_SCAN_LOG, OnScanLog)
        MESSAGE_HANDLER_EX(WM_SCAN_PROGRESS, OnScanProgress)
        MESSAGE_HANDLER_EX(WM_SCAN_DONE, OnScanDone)
        CHAIN_MSG_MAP(CDialogResize<MainDlg>)
    END_MSG_MAP()

    BEGIN_DLGRESIZE_MAP(MainDlg)
        DLGRESIZE_CONTROL(IDC_GRP_PATHS,     DLSZ_SIZE_X)
        DLGRESIZE_CONTROL(IDC_FOLDER_PATH,    DLSZ_SIZE_X)
        DLGRESIZE_CONTROL(IDC_BROWSE_FOLDER,  DLSZ_MOVE_X)
        DLGRESIZE_CONTROL(IDC_OUTPUT_PATH,    DLSZ_SIZE_X)
        DLGRESIZE_CONTROL(IDC_BROWSE_OUTPUT,  DLSZ_MOVE_X)
        DLGRESIZE_CONTROL(IDC_GRP_MUTATION,   DLSZ_MOVE_X)
        DLGRESIZE_CONTROL(IDC_ENABLE_MUTATION, DLSZ_MOVE_X)
        DLGRESIZE_CONTROL(IDC_LBL_MAXOFFSET,  DLSZ_MOVE_X)
        DLGRESIZE_CONTROL(IDC_MAX_MUTATION_OFFSET, DLSZ_MOVE_X)
        DLGRESIZE_CONTROL(IDC_SCAN,           DLSZ_MOVE_X)
        DLGRESIZE_CONTROL(IDC_STATUS,         DLSZ_SIZE_X)
        DLGRESIZE_CONTROL(IDC_ELAPSED,        DLSZ_MOVE_X)
        DLGRESIZE_CONTROL(IDC_GADGET_COUNT,   DLSZ_MOVE_X)
        DLGRESIZE_CONTROL(IDC_PROGRESS,       DLSZ_SIZE_X)
        DLGRESIZE_CONTROL(IDC_GRP_LOG,        DLSZ_SIZE_X | DLSZ_SIZE_Y)
        DLGRESIZE_CONTROL(IDC_LOG,            DLSZ_SIZE_X | DLSZ_SIZE_Y)
    END_DLGRESIZE_MAP()

private:
    BOOL OnInitDialog(CWindow wndFocus, LPARAM lInitParam);
    void OnDestroy();
    void OnTimer(UINT_PTR timerId);
    void OnGetMinMaxInfo(LPMINMAXINFO mmi);
    void OnBrowseFolder(UINT uNotifyCode, int nID, CWindow wndCtl);
    void OnBrowseOutput(UINT uNotifyCode, int nID, CWindow wndCtl);
    void OnScan(UINT uNotifyCode, int nID, CWindow wndCtl);
    void OnToggleMutation(UINT uNotifyCode, int nID, CWindow wndCtl);
    void OnCancel(UINT uNotifyCode, int nID, CWindow wndCtl);
    LRESULT OnScanLog(UINT uMsg, WPARAM wParam, LPARAM lParam);
    LRESULT OnScanProgress(UINT uMsg, WPARAM wParam, LPARAM lParam);
    LRESULT OnScanDone(UINT uMsg, WPARAM wParam, LPARAM lParam);

    void AppendLog(const std::string& text);
    void RunScan();
    void UpdateMutationState();
    void UpdateElapsed();

    ScanConfig BuildScanConfig();
    librp::SearchOptions BuildSearchOptions();

    CProgressBarCtrl progressBar_;
    CFont logFont_;
    std::thread workerThread_;
    std::chrono::steady_clock::time_point scanStart_;
    bool scanning_ = false;
    SIZE minSize_ = {};
};

} // namespace gadgets
