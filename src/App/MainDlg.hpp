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

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "Core/Engine.hpp"
#include "Core/Settings.hpp"
#include "Resource.h"

namespace gadgets {

constexpr UINT WM_SCAN_DONE = WM_APP + 1;

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
        COMMAND_ID_HANDLER_EX(IDC_COPY, OnCopy)
        COMMAND_ID_HANDLER_EX(IDCANCEL, OnCancel)
        COMMAND_HANDLER_EX(IDC_FILTER, EN_CHANGE, OnFilterChanged)
        COMMAND_HANDLER_EX(IDC_MODULE_FILTER, CBN_SELCHANGE, OnModuleFilterChanged)
        NOTIFY_CODE_HANDLER_EX(TCN_SELCHANGE, OnTabChanged)
        NOTIFY_CODE_HANDLER_EX(LVN_GETDISPINFO, OnGetDispInfo)
        NOTIFY_CODE_HANDLER_EX(LVN_KEYDOWN, OnListKeyDown)
        MESSAGE_HANDLER_EX(WM_SCAN_DONE, OnScanDone)
        CHAIN_MSG_MAP(CDialogResize<MainDlg>)
    END_MSG_MAP()

    BEGIN_DLGRESIZE_MAP(MainDlg)
        DLGRESIZE_CONTROL(IDC_GRP_INPUT,        DLSZ_SIZE_X)
        DLGRESIZE_CONTROL(IDC_FOLDER_COMBO,     DLSZ_SIZE_X)
        DLGRESIZE_CONTROL(IDC_BROWSE_FOLDER,    DLSZ_MOVE_X)
        DLGRESIZE_CONTROL(IDC_GRP_OUTPUT,       DLSZ_SIZE_X)
        DLGRESIZE_CONTROL(IDC_OUTPUT_PATH,      DLSZ_SIZE_X)
        DLGRESIZE_CONTROL(IDC_BROWSE_OUTPUT,    DLSZ_MOVE_X)
        DLGRESIZE_CONTROL(IDC_RECURSIVE,        DLSZ_MOVE_X)
        DLGRESIZE_CONTROL(IDC_ELF,              DLSZ_MOVE_X)
        DLGRESIZE_CONTROL(IDC_GRP_SEARCH,       DLSZ_SIZE_X)
        DLGRESIZE_CONTROL(IDC_GRP_MUTATION,     DLSZ_MOVE_X)
        DLGRESIZE_CONTROL(IDC_ENABLE_MUTATION,  DLSZ_MOVE_X)
        DLGRESIZE_CONTROL(IDC_MUTATE_BRANCHES,  DLSZ_MOVE_X)
        DLGRESIZE_CONTROL(IDC_LBL_MAXOFFSET,    DLSZ_MOVE_X)
        DLGRESIZE_CONTROL(IDC_MAX_MUTATION_OFFSET, DLSZ_MOVE_X)
        DLGRESIZE_CONTROL(IDC_SCAN,             DLSZ_MOVE_Y)
        DLGRESIZE_CONTROL(IDC_STATUS,           DLSZ_SIZE_X | DLSZ_MOVE_Y)
        DLGRESIZE_CONTROL(IDC_ELAPSED,          DLSZ_SIZE_X | DLSZ_MOVE_Y)
        DLGRESIZE_CONTROL(IDC_ETA,              DLSZ_SIZE_X | DLSZ_MOVE_Y)
        DLGRESIZE_CONTROL(IDC_GADGET_COUNT,     DLSZ_SIZE_X | DLSZ_MOVE_Y)
        DLGRESIZE_CONTROL(IDC_PROGRESS,         DLSZ_SIZE_X | DLSZ_MOVE_Y)
        DLGRESIZE_CONTROL(IDC_TAB,              DLSZ_SIZE_X | DLSZ_SIZE_Y)
        DLGRESIZE_CONTROL(IDC_FILTER,           DLSZ_SIZE_X | DLSZ_SIZE_Y)
        DLGRESIZE_CONTROL(IDC_MODULE_FILTER,    DLSZ_SIZE_X | DLSZ_SIZE_Y)
        DLGRESIZE_CONTROL(IDC_COPY,             DLSZ_MOVE_X | DLSZ_MOVE_Y)
        DLGRESIZE_CONTROL(IDC_RESULTS_COUNT,    DLSZ_MOVE_X | DLSZ_MOVE_Y)
        DLGRESIZE_CONTROL(IDC_LIST,             DLSZ_SIZE_X | DLSZ_SIZE_Y)
        DLGRESIZE_CONTROL(IDC_LOG,              DLSZ_SIZE_X | DLSZ_SIZE_Y)
    END_DLGRESIZE_MAP()

private:
    // Message handlers
    BOOL OnInitDialog(CWindow wndFocus, LPARAM lInitParam);
    void OnDestroy();
    void OnTimer(UINT_PTR timerId);
    void OnGetMinMaxInfo(LPMINMAXINFO mmi);
    void OnBrowseFolder(UINT uNotifyCode, int nID, CWindow wndCtl);
    void OnBrowseOutput(UINT uNotifyCode, int nID, CWindow wndCtl);
    void OnScan(UINT uNotifyCode, int nID, CWindow wndCtl);
    void OnToggleMutation(UINT uNotifyCode, int nID, CWindow wndCtl);
    void OnCopy(UINT uNotifyCode, int nID, CWindow wndCtl);
    void OnCancel(UINT uNotifyCode, int nID, CWindow wndCtl);
    LRESULT OnFilterChanged(WORD wNotifyCode, WORD wID, HWND hwndCtl);
    LRESULT OnModuleFilterChanged(WORD wNotifyCode, WORD wID, HWND hwndCtl);
    LRESULT OnTabChanged(NMHDR* pnmh);
    LRESULT OnGetDispInfo(NMHDR* pnmh);
    LRESULT OnListKeyDown(NMHDR* pnmh);
    LRESULT OnScanDone(UINT uMsg, WPARAM wParam, LPARAM lParam);

    // Helpers
    void StartScan();
    void CancelScan();
    void UpdateUiFromSnapshot();
    void DrainLog();
    void AppendLog(const std::string& text);
    void UpdateMutationState();
    void BuildRows();
    void ApplyFilter();
    void CopyToClipboard(bool selectedOnly);
    std::wstring RowText(size_t filteredIndex) const;

    RunConfig BuildConfig();
    void LoadSettingsToUi();
    void SaveSettingsFromUi();
    void SetTab(int index);
    void ShowPane(int index);

    // Controls
    CProgressBarCtrl progressBar_;
    CListViewCtrl list_;
    CTabCtrl tab_;
    CComboBox formatCombo_;
    CComboBox moduleCombo_;
    CFont monoFont_;

    // Scan state
    std::thread worker_;
    StopToken stop_;
    std::unique_ptr<Engine> engine_;
    std::atomic<bool> scanning_{false};
    std::chrono::steady_clock::time_point scanStart_;

    // Log drain
    std::mutex logMu_;
    std::vector<std::string> logQueue_;

    // Results view
    struct Row {
        size_t module;     // index into engine results (main or mutated list)
        size_t gadget;     // index into module gadgets
        bool mutated;      // main list or mutated list
    };
    std::vector<Row> rows_;
    std::vector<Row> filtered_;

    Settings settings_;
    SIZE minSize_ = {};
    int activeTab_ = 0;
};

} // namespace gadgets
