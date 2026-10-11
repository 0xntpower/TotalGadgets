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

    // Status bar panes, left to right.
    enum {
        kPaneStatus = 0,
        kPaneCounts = 1,
        kPaneElapsed = 2,
        kPaneEta = 3
    };

    BEGIN_MSG_MAP(MainDlg)
        MSG_WM_INITDIALOG(OnInitDialog)
        MSG_WM_DESTROY(OnDestroy)
        MSG_WM_TIMER(OnTimer)
        MSG_WM_GETMINMAXINFO(OnGetMinMaxInfo)
        MSG_WM_SIZE(OnSize)
        MSG_WM_INITMENUPOPUP(OnInitMenuPopup)
        COMMAND_ID_HANDLER_EX(IDC_BROWSE_FOLDER, OnBrowseFolder)
        COMMAND_ID_HANDLER_EX(IDC_BROWSE_OUTPUT, OnBrowseOutput)
        COMMAND_ID_HANDLER_EX(IDC_SCAN, OnScan)
        COMMAND_ID_HANDLER_EX(IDC_ENABLE_MUTATION, OnToggleMutation)
        COMMAND_ID_HANDLER_EX(IDC_COPY, OnCopy)
        COMMAND_ID_HANDLER_EX(IDCANCEL, OnCancel)
        COMMAND_ID_HANDLER_EX(ID_EDIT_COPY_SEL, OnMenuCopySelected)
        COMMAND_ID_HANDLER_EX(ID_EDIT_COPY_ALL, OnMenuCopyAll)
        COMMAND_ID_HANDLER_EX(ID_VIEW_GADGETS, OnViewGadgets)
        COMMAND_ID_HANDLER_EX(ID_VIEW_LOG, OnViewLog)
        COMMAND_ID_HANDLER_EX(ID_TOOLS_OPEN_OUTPUT, OnOpenOutputFolder)
        COMMAND_ID_HANDLER_EX(ID_HELP_ABOUT, OnAbout)
        COMMAND_RANGE_HANDLER_EX(ID_MRU_FOLDER0, ID_MRU_FOLDER0 + 7, OnMruFolder)
        COMMAND_HANDLER_EX(IDC_FILTER, EN_CHANGE, OnFilterChanged)
        COMMAND_HANDLER_EX(IDC_MODULE_FILTER, CBN_SELCHANGE, OnModuleFilterChanged)
        NOTIFY_CODE_HANDLER_EX(TCN_SELCHANGE, OnTabChanged)
        NOTIFY_CODE_HANDLER_EX(LVN_GETDISPINFO, OnGetDispInfo)
        NOTIFY_CODE_HANDLER_EX(LVN_COLUMNCLICK, OnColumnClick)
        NOTIFY_CODE_HANDLER_EX(NM_RCLICK, OnListRightClick)
        NOTIFY_CODE_HANDLER_EX(NM_DBLCLK, OnListDoubleClick)
        MESSAGE_HANDLER_EX(WM_SCAN_DONE, OnScanDone)
        CHAIN_MSG_MAP(CDialogResize<MainDlg>)
    END_MSG_MAP()

    BEGIN_DLGRESIZE_MAP(MainDlg)
        DLGRESIZE_CONTROL(IDC_GRP_INPUT,        DLSZ_SIZE_X)
        DLGRESIZE_CONTROL(IDC_FOLDER_COMBO,     DLSZ_SIZE_X)
        DLGRESIZE_CONTROL(IDC_BROWSE_FOLDER,    DLSZ_MOVE_X)
        DLGRESIZE_CONTROL(IDC_RECURSIVE,        DLSZ_MOVE_X)
        DLGRESIZE_CONTROL(IDC_ELF,              DLSZ_MOVE_X)
        DLGRESIZE_CONTROL(IDC_GRP_OUTPUT,       DLSZ_SIZE_X)
        DLGRESIZE_CONTROL(IDC_OUTPUT_PATH,      DLSZ_SIZE_X)
        DLGRESIZE_CONTROL(IDC_BROWSE_OUTPUT,    DLSZ_MOVE_X)
        DLGRESIZE_CONTROL(IDC_GRP_SEARCH,       DLSZ_SIZE_X)
        DLGRESIZE_CONTROL(IDC_GRP_MUTATION,     DLSZ_SIZE_X)
        DLGRESIZE_CONTROL(IDC_SCAN,             DLSZ_MOVE_Y)
        DLGRESIZE_CONTROL(IDC_PROGRESS,         DLSZ_SIZE_X | DLSZ_MOVE_Y)
        DLGRESIZE_CONTROL(IDC_TAB,              DLSZ_SIZE_X | DLSZ_SIZE_Y)
        DLGRESIZE_CONTROL(IDC_FILTER_LBL,       DLSZ_SIZE_Y)
        DLGRESIZE_CONTROL(IDC_FILTER,           DLSZ_SIZE_X | DLSZ_SIZE_Y)
        DLGRESIZE_CONTROL(IDC_MODULE_FILTER,    DLSZ_SIZE_X | DLSZ_SIZE_Y)
        DLGRESIZE_CONTROL(IDC_COPY,             DLSZ_MOVE_X | DLSZ_MOVE_Y)
        DLGRESIZE_CONTROL(IDC_RESULTS_COUNT,    DLSZ_MOVE_X | DLSZ_MOVE_Y)
        DLGRESIZE_CONTROL(IDC_LIST,             DLSZ_SIZE_X | DLSZ_SIZE_Y)
        DLGRESIZE_CONTROL(IDC_LOG,              DLSZ_SIZE_X | DLSZ_SIZE_Y)
        DLGRESIZE_CONTROL(IDC_STATUSBAR,        DLSZ_SIZE_X | DLSZ_MOVE_Y)
    END_DLGRESIZE_MAP()

private:
    // Message handlers
    BOOL OnInitDialog(CWindow wndFocus, LPARAM lInitParam);
    void OnDestroy();
    void OnTimer(UINT_PTR timerId);
    void OnGetMinMaxInfo(LPMINMAXINFO mmi);
    void OnSize(UINT nType, CSize size);
    void OnInitMenuPopup(CMenuHandle menu, UINT uPos, BOOL bSysMenu);
    void OnBrowseFolder(UINT uNotifyCode, int nID, CWindow wndCtl);
    void OnBrowseOutput(UINT uNotifyCode, int nID, CWindow wndCtl);
    void OnScan(UINT uNotifyCode, int nID, CWindow wndCtl);
    void OnToggleMutation(UINT uNotifyCode, int nID, CWindow wndCtl);
    void OnCopy(UINT uNotifyCode, int nID, CWindow wndCtl);
    void OnCancel(UINT uNotifyCode, int nID, CWindow wndCtl);
    void OnMenuCopySelected(UINT uNotifyCode, int nID, CWindow wndCtl);
    void OnMenuCopyAll(UINT uNotifyCode, int nID, CWindow wndCtl);
    void OnViewGadgets(UINT uNotifyCode, int nID, CWindow wndCtl);
    void OnViewLog(UINT uNotifyCode, int nID, CWindow wndCtl);
    void OnOpenOutputFolder(UINT uNotifyCode, int nID, CWindow wndCtl);
    void OnAbout(UINT uNotifyCode, int nID, CWindow wndCtl);
    void OnMruFolder(UINT uNotifyCode, int nID, CWindow wndCtl);
    LRESULT OnFilterChanged(WORD wNotifyCode, WORD wID, HWND hwndCtl);
    LRESULT OnModuleFilterChanged(WORD wNotifyCode, WORD wID, HWND hwndCtl);
    LRESULT OnTabChanged(NMHDR* pnmh);
    LRESULT OnGetDispInfo(NMHDR* pnmh);
    LRESULT OnColumnClick(NMHDR* pnmh);
    LRESULT OnListRightClick(NMHDR* pnmh);
    LRESULT OnListDoubleClick(NMHDR* pnmh);
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
    void SortFiltered();
    void UpdateSortIndicators();
    void CopyToClipboard(bool selectedOnly);
    void CopyFocusedControl();
    std::wstring RowText(size_t filteredIndex) const;
    void OpenOutputInExplorer() const;
    void ShowAboutBox();
    void CopyTextToClipboard(const std::wstring& text);

    struct Row; // defined below; used by the sort helpers
    const ModuleGadgets& RowModule(const Row& row) const;
    bool RowLess(const Row& a, const Row& b) const;

    RunConfig BuildConfig();
    void LoadSettingsToUi();
    void SaveSettingsFromUi();
    void SaveLayout();
    void ApplySavedPlacement();
    void LoadColumnWidths();
    void SetTab(int index);
    void ShowPane(int index);
    void UpdateStatusParts(int cx);
    void SetPane(int pane, const wchar_t* text);
    void SetTitle(const wchar_t* text);

    // Controls
    CProgressBarCtrl progressBar_;
    CListViewCtrl list_;
    CTabCtrl tab_;
    CComboBox formatCombo_;
    CComboBox moduleCombo_;
    CStatusBarCtrl statusBar_;
    CFont monoFont_;

    // Scan state
    std::thread worker_;
    StopToken stop_;
    std::unique_ptr<Engine> engine_;
    std::atomic<bool> scanning_{false};
    std::chrono::steady_clock::time_point scanStart_;
    bool marqueeOn_ = false;

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
    int sortCol_ = -1;
    bool sortAsc_ = true;

    Settings settings_;
    SIZE minSize_ = {};
    int activeTab_ = 0;
};

} // namespace gadgets
