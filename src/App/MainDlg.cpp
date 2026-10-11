#include "MainDlg.hpp"

#include <algorithm>
#include <filesystem>

#include <shellapi.h>

#include "Core/Sink.hpp"
#include "Core/Util.hpp"
#include "Defaults.hpp"

namespace gadgets {

namespace {
std::wstring GetDlgItemWText(HWND dlg, int id) {
    wchar_t buf[4096];
    *buf = L'\0';
    UINT copied = ::GetDlgItemTextW(dlg, id, buf, 4096);
    return std::wstring(buf, copied);
}

int StricmpAscii(const std::string& a, const std::string& b) {
    return ::CompareStringA(LOCALE_INVARIANT, 0, a.c_str(),
                            static_cast<int>(a.size()), b.c_str(),
                            static_cast<int>(b.size())) - CSTR_EQUAL;
}

// About box via the native task dialog (Vista+).
class CAboutTaskDialog : public CTaskDialogImpl<CAboutTaskDialog> {
public:
    CAboutTaskDialog() {
        SetWindowTitle(L"About Total Gadgets");
        SetMainInstructionText(L"Total Gadgets v2");
        SetContentText(
            L"Bulk ROP gadget extraction for Windows binaries.\n\n"
            L"Main pass: librp (rp++ engine, BeaEngine)\n"
            L"Mutation pass: capstone second decoder\n\n"
            L"MIT License. Results are provided for defensive research.");
        SetMainIcon(TD_INFORMATION_ICON);
        static TASKDIALOG_BUTTON buttons[] = {{IDOK, L"OK"}};
        SetButtons(buttons, 1);
        ModifyFlags(0, TDF_ALLOW_DIALOG_CANCELLATION);
    }
};

} // namespace



// ---------------------------------------------------------------------------
// Init / teardown
// ---------------------------------------------------------------------------

BOOL MainDlg::OnInitDialog(CWindow /*wndFocus*/, LPARAM /*lInitParam*/) {
    HICON hIcon = AtlLoadIconImage(IDR_MAINFRAME, LR_DEFAULTCOLOR,
                                   ::GetSystemMetrics(SM_CXICON),
                                   ::GetSystemMetrics(SM_CYICON));
    SetIcon(hIcon, TRUE);
    HICON hIconSmall = AtlLoadIconImage(IDR_MAINFRAME, LR_DEFAULTCOLOR,
                                        ::GetSystemMetrics(SM_CXSMICON),
                                        ::GetSystemMetrics(SM_CYSMICON));
    SetIcon(hIconSmall, FALSE);

    DlgResize_Init(false, true, 0); // no gripper control: the status bar has one

    // The designed size is the minimum track size; capture it before the
    // saved placement is restored.
    {
        CRect rc;
        GetWindowRect(&rc);
        minSize_ = {rc.Width(), rc.Height()};
    }

    // Controls
    progressBar_ = GetDlgItem(IDC_PROGRESS);
    progressBar_.SetRange(0, 100);
    progressBar_.SetPos(0);

    list_ = GetDlgItem(IDC_LIST);
    list_.SetExtendedListViewStyle(LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER |
                                   LVS_EX_LABELTIP | LVS_EX_INFOTIP);
    list_.AddColumn(L"Src", 0);
    list_.AddColumn(L"Module", 1);
    list_.AddColumn(L"Address", 2);
    list_.AddColumn(L"Disassembly", 3);
    list_.AddColumn(L"Bytes", 4);
    list_.AddColumn(L"Found", 5);
    list_.SetColumnWidth(0, 44);
    list_.SetColumnWidth(1, 110);
    list_.SetColumnWidth(2, 150);
    list_.SetColumnWidth(3, 380);
    list_.SetColumnWidth(4, 160);
    list_.SetColumnWidth(5, 48);

    tab_ = GetDlgItem(IDC_TAB);
    tab_.InsertItem(0, L"Gadgets");
    tab_.InsertItem(1, L"Log");

    formatCombo_ = GetDlgItem(IDC_FORMAT);
    formatCombo_.AddString(L"Text (rp++)");
    formatCombo_.AddString(L"JSON");
    formatCombo_.AddString(L"CSV");
    formatCombo_.SetCurSel(0);

    moduleCombo_ = GetDlgItem(IDC_MODULE_FILTER);
    moduleCombo_.AddString(L"All modules");
    moduleCombo_.SetCurSel(0);
    moduleCombo_.EnableWindow(FALSE);

    statusBar_ = GetDlgItem(IDC_STATUSBAR);
    UpdateStatusParts(0);

    monoFont_.CreateFont(
        kMonoFontSize, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, kMonoFontName);
    CEdit logCtrl(GetDlgItem(IDC_LOG));
    logCtrl.SetFont(monoFont_);
    CEdit filterCtrl(GetDlgItem(IDC_FILTER));
    filterCtrl.SetFont(monoFont_);
    ::SendMessageW(filterCtrl, EM_SETCUEBANNER, FALSE,
                   reinterpret_cast<LPARAM>(L"Search disassembly, module, or address"));

    // Defaults
    SetDlgItemInt(IDC_MAX_GADGET_LEN, 5, FALSE);
    SetDlgItemInt(IDC_MAX_THREADS, Engine::DefaultThreads(), FALSE);
    SetDlgItemInt(IDC_MAX_MUTATION_OFFSET, kDefaultMutationLookback, FALSE);

    settings_.Load();
    LoadSettingsToUi();
    LoadColumnWidths();
    ApplySavedPlacement();

    SetTab(0);
    UpdateMutationState();

    SetPane(kPaneStatus, L"Ready");
    SetTitle(nullptr);

    return TRUE;
}

void MainDlg::OnDestroy() {
    KillTimer(kUiTimerId);
    KillTimer(kFilterDebounceId);
    if (worker_.joinable())
        worker_.join();
    SaveLayout();
    ::PostQuitMessage(0);
}

void MainDlg::SaveLayout() {
    WINDOWPLACEMENT wp = {};
    wp.length = sizeof(WINDOWPLACEMENT);
    if (GetWindowPlacement(&wp)) {
        const RECT& r = wp.rcNormalPosition;
        settings_.winX = r.left;
        settings_.winY = r.top;
        settings_.winCx = r.right - r.left;
        settings_.winCy = r.bottom - r.top;
        settings_.winMaximized = (wp.showCmd == SW_SHOWMAXIMIZED);
    }
    for (int i = 0; i < Settings::kColumnCount; ++i)
        settings_.columnWidths[i] = list_.GetColumnWidth(i);
    settings_.Save();
}

void MainDlg::ApplySavedPlacement() {
    CRect target(settings_.winX, settings_.winY,
                 settings_.winX + settings_.winCx,
                 settings_.winY + settings_.winCy);
    const bool valid = settings_.winX >= 0 && settings_.winCx > 0 &&
                       ::MonitorFromRect(target, MONITOR_DEFAULTTONULL) !=
                           nullptr;
    if (!valid) {
        CenterWindow();
        return;
    }
    SetWindowPos(nullptr, settings_.winX, settings_.winY,
                 settings_.winCx, settings_.winCy,
                 SWP_NOZORDER | SWP_NOACTIVATE);
    if (settings_.winMaximized)
        ShowWindow(SW_MAXIMIZE);
}

void MainDlg::LoadColumnWidths() {
    for (int i = 0; i < Settings::kColumnCount; ++i)
        if (settings_.columnWidths[i] > 0)
            list_.SetColumnWidth(i, settings_.columnWidths[i]);
}

void MainDlg::LoadSettingsToUi() {
    for (const auto& folder : settings_.mruFolders)
        SendDlgItemMessageW(IDC_FOLDER_COMBO, CB_ADDSTRING, 0,
                            reinterpret_cast<LPARAM>(folder.c_str()));
    if (!settings_.lastOutput.empty())
        ::SetDlgItemTextW(m_hWnd, IDC_OUTPUT_PATH, settings_.lastOutput.c_str());
    else
        ::SetDlgItemTextW(m_hWnd, IDC_OUTPUT_PATH, L"gadgets.txt");

    CheckDlgButton(IDC_RECURSIVE, settings_.scan.recursive ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(IDC_ELF, settings_.scan.includeElf ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(IDC_UNIQUE_ONLY, settings_.scan.uniqueOnly ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(IDC_ALLOW_BRANCHES,
                   settings_.scan.allowBranches ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(IDC_ENABLE_MUTATION,
                   settings_.mutation.enabled ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(IDC_MUTATE_BRANCHES,
                   settings_.mutation.allowBranches ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(IDC_OPEN_WHEN_DONE,
                   settings_.openWhenDone ? BST_CHECKED : BST_UNCHECKED);
    SetDlgItemInt(IDC_MAX_GADGET_LEN, settings_.scan.maxGadgetLen, FALSE);
    if (settings_.scan.threads > 0)
        SetDlgItemInt(IDC_MAX_THREADS, settings_.scan.threads, FALSE);
    SetDlgItemInt(IDC_MAX_MUTATION_OFFSET, settings_.mutation.lookback, FALSE);

    if (!settings_.scan.badBytes.empty()) {
        std::string hex = util::BytesToHex(settings_.scan.badBytes.data(),
                                           settings_.scan.badBytes.size());
        SetDlgItemTextA(m_hWnd, IDC_BAD_BYTES, hex.c_str());
    }

    formatCombo_.SetCurSel(static_cast<int>(settings_.format));
    CheckDlgButton(IDC_SPLIT,
                   settings_.mode == OutputMode::PerModule ? BST_CHECKED
                                                          : BST_UNCHECKED);
    UpdateMutationState();
}

void MainDlg::SaveSettingsFromUi() {
    settings_.scan.recursive =
        IsDlgButtonChecked(IDC_RECURSIVE) == BST_CHECKED;
    settings_.scan.includeElf = IsDlgButtonChecked(IDC_ELF) == BST_CHECKED;
    settings_.scan.uniqueOnly =
        IsDlgButtonChecked(IDC_UNIQUE_ONLY) == BST_CHECKED;
    settings_.scan.allowBranches =
        IsDlgButtonChecked(IDC_ALLOW_BRANCHES) == BST_CHECKED;
    settings_.scan.maxGadgetLen =
        std::max<UINT>(1, GetDlgItemInt(IDC_MAX_GADGET_LEN, nullptr, FALSE));
    settings_.scan.threads =
        GetDlgItemInt(IDC_MAX_THREADS, nullptr, FALSE);
    std::vector<uint8_t> bad;
    char badBuf[256] = {};
    ::GetDlgItemTextA(m_hWnd, IDC_BAD_BYTES, badBuf, sizeof(badBuf));
    if (util::ParseHexBytes(badBuf, bad))
        settings_.scan.badBytes = std::move(bad);

    settings_.mutation.enabled =
        IsDlgButtonChecked(IDC_ENABLE_MUTATION) == BST_CHECKED;
    settings_.mutation.allowBranches =
        IsDlgButtonChecked(IDC_MUTATE_BRANCHES) == BST_CHECKED;
    settings_.mutation.lookback = std::max<UINT>(
        1, GetDlgItemInt(IDC_MAX_MUTATION_OFFSET, nullptr, FALSE));

    settings_.openWhenDone =
        IsDlgButtonChecked(IDC_OPEN_WHEN_DONE) == BST_CHECKED;

    settings_.format = static_cast<OutputFormat>(formatCombo_.GetCurSel());
    settings_.mode = (IsDlgButtonChecked(IDC_SPLIT) == BST_CHECKED)
                         ? OutputMode::PerModule
                         : OutputMode::SingleFile;
    settings_.lastOutput = GetDlgItemWText(m_hWnd, IDC_OUTPUT_PATH);

    settings_.Save();
}

// ---------------------------------------------------------------------------
// Resize / timer plumbing
// ---------------------------------------------------------------------------

void MainDlg::OnGetMinMaxInfo(LPMINMAXINFO mmi) {
    if (minSize_.cx > 0) {
        mmi->ptMinTrackSize.x = minSize_.cx;
        mmi->ptMinTrackSize.y = minSize_.cy;
    }
}

void MainDlg::OnSize(UINT nType, CSize size) {
    SetMsgHandled(FALSE); // CDialogResize lays out controls first
    if (statusBar_.m_hWnd != nullptr)
        UpdateStatusParts(size.cx);
}

void MainDlg::UpdateStatusParts(int cx) {
    if (cx <= 0) {
        CRect rc;
        statusBar_.GetClientRect(&rc);
        cx = rc.Width();
    }
    const int kPane1 = 170; // counts
    const int kPane2 = 86;  // elapsed
    const int kPane3 = 104; // ETA
    int edges[3];
    edges[0] = std::max(cx - kPane1 - kPane2 - kPane3, 80);
    edges[1] = std::max(cx - kPane2 - kPane3, edges[0] + 40);
    edges[2] = std::max(cx - kPane3, edges[1] + 40);
    statusBar_.SetParts(3, edges);
}

void MainDlg::SetPane(int pane, const wchar_t* text) {
    statusBar_.SendMessage(SB_SETTEXTW, MAKEWPARAM(pane, 0),
                          reinterpret_cast<LPARAM>(text));
}

void MainDlg::OnTimer(UINT_PTR timerId) {
    if (timerId == kFilterDebounceId) {
        KillTimer(kFilterDebounceId);
        ApplyFilter();
        return;
    }
    if (timerId != kUiTimerId || !scanning_.load())
        return;
    UpdateUiFromSnapshot();
    DrainLog();
}

void MainDlg::UpdateUiFromSnapshot() {
    if (!engine_)
        return;

    const auto snap = engine_->Snapshot();

    // Phase transitions: marquee while enumerating, smooth bar otherwise.
    if (snap.phase == Phase::Enumerating && !marqueeOn_) {
        marqueeOn_ = true;
        ::SendMessageW(progressBar_, PBM_SETMARQUEE, TRUE, 30);
    } else if (snap.phase != Phase::Enumerating && marqueeOn_) {
        marqueeOn_ = false;
        ::SendMessageW(progressBar_, PBM_SETMARQUEE, FALSE, 0);
        progressBar_.SetRange(0, 100);
    }

    int pct = 0;
    switch (snap.phase) {
    case Phase::Scanning:
        if (snap.bytesTotal > 0)
            pct = static_cast<int>(snap.bytesDone * 100 / snap.bytesTotal);
        break;
    case Phase::Mutating:
        if (snap.filesTotal > 0)
            pct = static_cast<int>(snap.filesDone * 100 / snap.filesTotal);
        break;
    default:
        break;
    }
    if (!marqueeOn_)
        progressBar_.SetPos(pct);

    std::wstring status;
    switch (snap.phase) {
    case Phase::Enumerating: status = L"Enumerating files..."; break;
    case Phase::Scanning:
        status = L"Scanning: " + snap.currentFile;
        break;
    case Phase::Mutating:
        status = L"Mutating: " + snap.currentFile;
        break;
    default: break;
    }
    if (stop_.Stopped())
        status = L"Cancelling... " + status;
    if (!status.empty())
        SetPane(kPaneStatus, status.c_str());

    const auto elapsed = std::chrono::duration<double>(
                             std::chrono::steady_clock::now() - scanStart_)
                             .count();
    SetPane(kPaneElapsed,
            util::ToWide(util::FormatElapsed(elapsed)).c_str());

    std::wstring eta = L"--";
    if (snap.phase == Phase::Scanning && snap.bytesDone > 0 && elapsed > 0.5) {
        const double rate = snap.bytesDone / elapsed;
        if (snap.bytesTotal > snap.bytesDone && rate > 1.0) {
            const double remain = (snap.bytesTotal - snap.bytesDone) / rate;
            eta = util::ToWide(util::FormatElapsed(remain));
        } else {
            eta = L"soon";
        }
    }
    SetPane(kPaneEta, (L"ETA " + eta).c_str());

    std::wstring counts = util::ToWide(util::FormatCount(snap.gadgetsFound));
    if (snap.mutatedFound > 0)
        counts += L" +" + util::ToWide(util::FormatCount(snap.mutatedFound)) +
                  L" mut";
    SetPane(kPaneCounts, counts.c_str());

    // Title mirrors progress, Explorer-style, so minimized scans are visible.
    if (snap.phase == Phase::Scanning || snap.phase == Phase::Mutating) {
        wchar_t title[64];
        swprintf_s(title, L"Total Gadgets v2 - %s %d%%",
                   snap.phase == Phase::Scanning ? L"Scanning" : L"Mutating",
                   pct);
        SetWindowTextW(title);
    }
}

void MainDlg::SetTitle(const wchar_t* text) {
    SetWindowTextW(text ? text : L"Total Gadgets v2");
}

void MainDlg::DrainLog() {
    std::vector<std::string> batch;
    {
        std::lock_guard<std::mutex> lock(logMu_);
        batch.swap(logQueue_);
    }
    if (batch.empty())
        return;

    std::string joined;
    for (const auto& line : batch)
        joined += line + "\r\n";

    CEdit logCtrl(GetDlgItem(IDC_LOG));
    int len = logCtrl.GetWindowTextLength();
    logCtrl.SetSel(len, len);
    logCtrl.ReplaceSel(CString(util::ToWide(joined).c_str()));
}

void MainDlg::AppendLog(const std::string& text) {
    CEdit logCtrl(GetDlgItem(IDC_LOG));
    int len = logCtrl.GetWindowTextLength();
    logCtrl.SetSel(len, len);
    logCtrl.ReplaceSel(CString(util::ToWide(text + "\r\n").c_str()));
}

// ---------------------------------------------------------------------------
// Browsing
// ---------------------------------------------------------------------------

void MainDlg::OnBrowseFolder(UINT, int, CWindow) {
    CShellFileOpenDialog dlg(nullptr, FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM,
                             nullptr, nullptr, 0);
    dlg.GetPtr()->SetTitle(L"Select folder containing binaries");
    if (dlg.DoModal(m_hWnd) == IDOK) {
        wchar_t path[MAX_PATH * 4] = {};
        dlg.GetFilePath(path, MAX_PATH * 4);
        ::SetDlgItemTextW(m_hWnd, IDC_FOLDER_COMBO, path);
    }
}

void MainDlg::OnBrowseOutput(UINT, int, CWindow) {
    if (IsDlgButtonChecked(IDC_SPLIT) == BST_CHECKED) {
        CShellFileOpenDialog dlg(nullptr, FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM,
                                 nullptr, nullptr, 0);
        dlg.GetPtr()->SetTitle(L"Select output directory (one file per module)");
        if (dlg.DoModal(m_hWnd) == IDOK) {
            wchar_t path[MAX_PATH * 4] = {};
            dlg.GetFilePath(path, MAX_PATH * 4);
            ::SetDlgItemTextW(m_hWnd, IDC_OUTPUT_PATH, path);
        }
        return;
    }

    const COMDLG_FILTERSPEC filter[] = {
        { L"Text Files", L"*.txt" },
        { L"JSON", L"*.json" },
        { L"CSV", L"*.csv" },
        { L"All Files", L"*.*" }
    };
    CShellFileSaveDialog dlg(L"gadgets.txt",
                             FOS_OVERWRITEPROMPT | FOS_FORCEFILESYSTEM,
                             L"txt", filter, _countof(filter));
    dlg.GetPtr()->SetTitle(L"Save gadget output");
    if (dlg.DoModal(m_hWnd) == IDOK) {
        wchar_t path[MAX_PATH * 4] = {};
        dlg.GetFilePath(path, MAX_PATH * 4);
        ::SetDlgItemTextW(m_hWnd, IDC_OUTPUT_PATH, path);
    }
}

// ---------------------------------------------------------------------------
// Scan lifecycle
// ---------------------------------------------------------------------------

RunConfig MainDlg::BuildConfig() {
    RunConfig cfg;
    cfg.scan.maxGadgetLen =
        std::max<UINT>(1, GetDlgItemInt(IDC_MAX_GADGET_LEN, nullptr, FALSE));
    cfg.scan.threads = GetDlgItemInt(IDC_MAX_THREADS, nullptr, FALSE);
    cfg.scan.uniqueOnly = IsDlgButtonChecked(IDC_UNIQUE_ONLY) == BST_CHECKED;
    cfg.scan.allowBranches =
        IsDlgButtonChecked(IDC_ALLOW_BRANCHES) == BST_CHECKED;
    cfg.scan.recursive = IsDlgButtonChecked(IDC_RECURSIVE) == BST_CHECKED;
    cfg.scan.includeElf = IsDlgButtonChecked(IDC_ELF) == BST_CHECKED;

    char badBuf[256] = {};
    ::GetDlgItemTextA(m_hWnd, IDC_BAD_BYTES, badBuf, sizeof(badBuf));
    util::ParseHexBytes(badBuf, cfg.scan.badBytes);

    cfg.mutation.enabled =
        IsDlgButtonChecked(IDC_ENABLE_MUTATION) == BST_CHECKED;
    cfg.mutation.lookback = std::max<UINT>(
        1, GetDlgItemInt(IDC_MAX_MUTATION_OFFSET, nullptr, FALSE));
    cfg.mutation.maxGadgetLen = cfg.scan.maxGadgetLen;
    cfg.mutation.allowBranches =
        IsDlgButtonChecked(IDC_MUTATE_BRANCHES) == BST_CHECKED;

    cfg.output.path = GetDlgItemWText(m_hWnd, IDC_OUTPUT_PATH);
    cfg.output.format = static_cast<OutputFormat>(formatCombo_.GetCurSel());
    cfg.output.mode = (IsDlgButtonChecked(IDC_SPLIT) == BST_CHECKED)
                          ? OutputMode::PerModule
                          : OutputMode::SingleFile;
    return cfg;
}

void MainDlg::OnScan(UINT, int, CWindow) {
    if (scanning_.load()) {
        CancelScan();
        return;
    }
    StartScan();
}

void MainDlg::StartScan() {
    const std::wstring folder = GetDlgItemWText(m_hWnd, IDC_FOLDER_COMBO);
    const std::wstring output = GetDlgItemWText(m_hWnd, IDC_OUTPUT_PATH);

    if (folder.empty() || output.empty()) {
        ::MessageBoxW(m_hWnd, L"Please specify both an input folder and output path.",
                      L"Total Gadgets", MB_OK | MB_ICONWARNING);
        return;
    }
    if (!std::filesystem::is_directory(std::filesystem::path(folder))) {
        ::MessageBoxW(m_hWnd, L"The specified input folder does not exist.",
                      L"Total Gadgets", MB_OK | MB_ICONERROR);
        return;
    }

    auto config = BuildConfig();
    if (config.output.mode == OutputMode::PerModule &&
        !std::filesystem::is_directory(config.output.path)) {
        if (::MessageBoxW(m_hWnd,
                          L"Output directory does not exist. Create it?",
                          L"Total Gadgets", MB_OKCANCEL | MB_ICONQUESTION) != IDOK)
            return;
        std::error_code ec;
        std::filesystem::create_directories(config.output.path, ec);
        if (ec) {
            ::MessageBoxW(m_hWnd, L"Cannot create the output directory.",
                          L"Total Gadgets", MB_OK | MB_ICONERROR);
            return;
        }
    }

    // Persist settings + MRU immediately so a crash mid-scan keeps them.
    settings_.PushMruFolder(folder);
    SaveSettingsFromUi();

    // Reset UI
    ::SetDlgItemTextW(m_hWnd, IDC_LOG, L"");
    progressBar_.SetPos(0);
    rows_.clear();
    filtered_.clear();
    sortCol_ = -1;
    UpdateSortIndicators();
    list_.SetItemCount(0);
    moduleCombo_.ResetContent();
    moduleCombo_.AddString(L"All modules");
    moduleCombo_.SetCurSel(0);
    moduleCombo_.EnableWindow(FALSE);
    ::SetDlgItemTextW(m_hWnd, IDC_RESULTS_COUNT, L"");

    scanning_.store(true);
    stop_.Reset();
    scanStart_ = std::chrono::steady_clock::now();
    marqueeOn_ = true; // the enumeration phase shows first
    ::SendMessageW(progressBar_, PBM_SETMARQUEE, TRUE, 30);

    ::SetDlgItemTextW(m_hWnd, IDC_SCAN, L"Cancel");
    ::EnableWindow(GetDlgItem(IDC_ENABLE_MUTATION), FALSE);
    SetPane(kPaneStatus, L"Starting...");
    SetPane(kPaneEta, L"");
    SetTitle(nullptr);

    engine_ = std::make_unique<Engine>(config, stop_, RunCallbacks{});
    {
        std::lock_guard<std::mutex> lock(logMu_);
        logQueue_.clear();
    }

    RunCallbacks cbs;
    cbs.onLog = [this](const std::string& msg) {
        std::lock_guard<std::mutex> lock(logMu_);
        logQueue_.push_back(msg);
    };
    cbs.onProgressChanged = [] {}; // timer pulls snapshots
    engine_->SetCallbacks(cbs);

    AppendLog("Scan started.");

    const HWND hwnd = m_hWnd;
    const std::filesystem::path target(folder);
    worker_ = std::thread([this, hwnd, target] {
        auto stats = engine_->Run({target});
        ::PostMessage(hwnd, WM_SCAN_DONE,
                      reinterpret_cast<WPARAM>(new ScanStats(stats)), 0);
    });

    SetTimer(kUiTimerId, kUiTimerIntervalMs);
}

void MainDlg::CancelScan() {
    stop_.Stop();
    ::SetDlgItemTextW(m_hWnd, IDC_SCAN, L"Cancelling...");
    ::EnableWindow(GetDlgItem(IDC_SCAN), FALSE);
}



LRESULT MainDlg::OnScanDone(UINT, WPARAM wParam, LPARAM) {
    std::unique_ptr<ScanStats> stats(reinterpret_cast<ScanStats*>(wParam));

    if (worker_.joinable())
        worker_.join();

    KillTimer(kUiTimerId);
    UpdateUiFromSnapshot();
    DrainLog();

    scanning_.store(false);
    marqueeOn_ = false;
    ::SendMessageW(progressBar_, PBM_SETMARQUEE, FALSE, 0);
    progressBar_.SetRange(0, 100);
    progressBar_.SetPos(stats->cancelled ? progressBar_.GetPos() : 100);

    ::SetDlgItemTextW(m_hWnd, IDC_SCAN, L"Scan");
    ::EnableWindow(GetDlgItem(IDC_SCAN), TRUE);
    ::EnableWindow(GetDlgItem(IDC_ENABLE_MUTATION), TRUE);

    wchar_t status[160];
    if (stats->cancelled) {
        swprintf_s(status, L"Cancelled - %s module(s) scanned",
                   util::ToWide(util::FormatCount(stats->filesScanned)).c_str());
    } else if (stats->filesFailed > 0 || !stats->outputWritten) {
        swprintf_s(status, L"Finished with errors (%s failed)",
                   util::ToWide(util::FormatCount(stats->filesFailed)).c_str());
    } else {
        swprintf_s(status, L"Done - %s module(s), %s gadgets",
                   util::ToWide(util::FormatCount(stats->filesScanned)).c_str(),
                   util::ToWide(util::FormatCount(stats->gadgetsFound)).c_str());
    }
    SetPane(kPaneStatus, status);
    SetPane(kPaneEta, L"");

    SetTitle(stats->cancelled ? L"Total Gadgets v2 - cancelled"
                              : L"Total Gadgets v2 - done");

    BuildRows();
    ApplyFilter();
    moduleCombo_.EnableWindow(moduleCombo_.GetCount() > 1);

    ::MessageBeep(stats->cancelled ? MB_ICONEXCLAMATION : MB_ICONASTERISK);

    if (settings_.openWhenDone && !stats->cancelled && stats->outputWritten)
        OpenOutputInExplorer();
    return 0;
}

void MainDlg::OnCancel(UINT, int nID, CWindow) {
    if (scanning_.load()) {
        CancelScan();
        return;
    }
    SaveSettingsFromUi();
    DestroyWindow();
}

// ---------------------------------------------------------------------------
// Results view
// ---------------------------------------------------------------------------

void MainDlg::BuildRows() {
    rows_.clear();
    if (!engine_)
        return;

    moduleCombo_.ResetContent();
    moduleCombo_.AddString(L"All modules");
    moduleCombo_.SetItemData(0, static_cast<DWORD_PTR>(-1));

    const auto fill = [&](const std::vector<ModuleGadgets>& mods, bool mutated) {
        for (size_t m = 0; m < mods.size(); ++m) {
            const auto& mod = mods[m];
            for (size_t g = 0; g < mod.gadgets.size(); ++g)
                rows_.push_back({m, g, mutated});

            std::wstring label = util::ToWide(mod.moduleName) +
                                 (mutated ? L" [mutated]" : L"");
            int item = moduleCombo_.AddString(label.c_str());
            moduleCombo_.SetItemData(
                item, static_cast<DWORD_PTR>(m * 2 + (mutated ? 1 : 0)));
        }
    };
    fill(engine_->Results(), false);
    fill(engine_->MutatedResults(), true);
    moduleCombo_.SetCurSel(0);
}

void MainDlg::ApplyFilter() {
    const std::wstring filterRaw = GetDlgItemWText(m_hWnd, IDC_FILTER);
    const std::string filter = util::ToLower(util::ToUtf8(filterRaw));

    const int sel = moduleCombo_.GetCurSel();
    const bool filterModule =
        sel > 0 && moduleCombo_.GetItemData(sel) != static_cast<DWORD_PTR>(-1);
    const DWORD_PTR moduleKey =
        filterModule ? moduleCombo_.GetItemData(sel) : 0;

    filtered_.clear();
    if (!engine_) {
        list_.SetItemCount(0);
        return;
    }

    const auto match = [&](const Row& row) {
        if (filterModule) {
            const DWORD_PTR key = row.module * 2 + (row.mutated ? 1 : 0);
            if (key != moduleKey)
                return false;
        }
        if (filter.empty())
            return true;
        const auto& mods = row.mutated ? engine_->MutatedResults()
                                       : engine_->Results();
        const auto& mod = mods[row.module];
        const auto& g = mod.gadgets[row.gadget];
        if (util::IContains(g.disassembly, filter))
            return true;
        if (util::IContains(mod.moduleName, filter))
            return true;
        const bool is64 = mod.arch != kArchX86 && mod.arch != kArchArm;
        if (util::IContains(util::FormatAddress(g.address, is64), filter))
            return true;
        return false;
    };

    for (const auto& row : rows_)
        if (match(row))
            filtered_.push_back(row);

    if (sortCol_ >= 0)
        SortFiltered();

    list_.SetItemCount(static_cast<int>(filtered_.size()));

    wchar_t count[96];
    swprintf_s(count, L"%s / %s rows",
               util::ToWide(util::FormatCount(filtered_.size())).c_str(),
               util::ToWide(util::FormatCount(rows_.size())).c_str());
    ::SetDlgItemTextW(m_hWnd, IDC_RESULTS_COUNT, count);
}

LRESULT MainDlg::OnFilterChanged(WORD, WORD, HWND) {
    // Debounce: filtering over a million rows should not re-run per
    // keystroke. Small result sets apply immediately.
    KillTimer(kFilterDebounceId);
    if (rows_.size() < 20000)
        ApplyFilter();
    else
        SetTimer(kFilterDebounceId, kFilterDebounceMs);
    return 0;
}

LRESULT MainDlg::OnModuleFilterChanged(WORD, WORD, HWND) {
    ApplyFilter();
    return 0;
}

// ---------------------------------------------------------------------------
// Sorting
// ---------------------------------------------------------------------------

const ModuleGadgets& MainDlg::RowModule(const Row& row) const {
    const auto& mods =
        row.mutated ? engine_->MutatedResults() : engine_->Results();
    return mods[row.module];
}

bool MainDlg::RowLess(const Row& a, const Row& b) const {
    const ModuleGadgets& ma = RowModule(a);
    const ModuleGadgets& mb = RowModule(b);
    const auto& ga = ma.gadgets[a.gadget];
    const auto& gb = mb.gadgets[b.gadget];

    int cmp = 0;
    switch (sortCol_) {
    case 0:
        cmp = static_cast<int>(a.mutated) - static_cast<int>(b.mutated);
        break;
    case 1:
        cmp = StricmpAscii(ma.moduleName, mb.moduleName);
        break;
    case 2:
        cmp = ga.address < gb.address ? -1 : ga.address > gb.address ? 1 : 0;
        break;
    case 3:
        cmp = StricmpAscii(ga.disassembly, gb.disassembly);
        break;
    case 4:
        cmp = StricmpAscii(util::BytesToHex(ga.bytes.data(), ga.bytes.size()),
                           util::BytesToHex(gb.bytes.data(), gb.bytes.size()));
        break;
    case 5:
        cmp = ga.numOccurrences < gb.numOccurrences
                  ? -1
                  : ga.numOccurrences > gb.numOccurrences ? 1 : 0;
        break;
    default:
        return false;
    }
    if (!sortAsc_)
        cmp = -cmp;
    if (cmp != 0)
        return cmp < 0;
    // Stable total order: mutated, then module, then underlying index.
    if (a.mutated != b.mutated)
        return !a.mutated;
    if (a.module != b.module)
        return a.module < b.module;
    return a.gadget < b.gadget;
}

void MainDlg::SortFiltered() {
    if (sortCol_ < 0 || !engine_ || filtered_.empty())
        return;
    const HCURSOR prev = ::SetCursor(::LoadCursor(nullptr, IDC_WAIT));
    std::stable_sort(filtered_.begin(), filtered_.end(),
                     [this](const Row& a, const Row& b) { return RowLess(a, b); });
    ::SetCursor(prev);
}

void MainDlg::UpdateSortIndicators() {
    CHeaderCtrl header = list_.GetHeader();
    if (!header)
        return;
    for (int i = 0; i < Settings::kColumnCount; ++i) {
        HDITEM hdi = {};
        hdi.mask = HDI_FORMAT;
        header.GetItem(i, &hdi);
        hdi.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
        if (i == sortCol_)
            hdi.fmt |= sortAsc_ ? HDF_SORTUP : HDF_SORTDOWN;
        header.SetItem(i, &hdi);
    }
}

LRESULT MainDlg::OnColumnClick(NMHDR* pnmh) {
    auto* lv = reinterpret_cast<NMLISTVIEW*>(pnmh);
    const int col = lv->iSubItem;
    if (sortCol_ == col)
        sortAsc_ = !sortAsc_;
    else {
        sortCol_ = col;
        sortAsc_ = true;
    }
    SortFiltered();
    UpdateSortIndicators();
    list_.SetItemCount(static_cast<int>(filtered_.size()));
    return 0;
}

// ---------------------------------------------------------------------------
// Data provider / clipboard
// ---------------------------------------------------------------------------

LRESULT MainDlg::OnGetDispInfo(NMHDR* pnmh) {
    auto* pdi = reinterpret_cast<NMLVDISPINFO*>(pnmh);
    if (!(pdi->item.mask & LVIF_TEXT) || !engine_)
        return 0;

    const size_t i = static_cast<size_t>(pdi->item.iItem);
    if (i >= filtered_.size())
        return 0;

    const auto& row = filtered_[i];
    const auto& mods =
        row.mutated ? engine_->MutatedResults() : engine_->Results();
    if (row.module >= mods.size())
        return 0;
    const auto& mod = mods[row.module];
    if (row.gadget >= mod.gadgets.size())
        return 0;
    const auto& g = mod.gadgets[row.gadget];

    std::wstring text;
    switch (pdi->item.iSubItem) {
    case 0:
        text = row.mutated ? L"mut" : L"scan";
        break;
    case 1:
        text = util::ToWide(mod.moduleName);
        break;
    case 2: {
        const bool is64 = mod.arch != kArchX86 && mod.arch != kArchArm;
        text = util::ToWide(util::FormatAddress(g.address, is64));
        break;
    }
    case 3:
        text = util::ToWide(g.disassembly);
        break;
    case 4:
        text = util::ToWide(util::BytesToHex(g.bytes.data(), g.bytes.size()));
        break;
    case 5:
        text = std::to_wstring(g.numOccurrences);
        break;
    default:
        return 0;
    }

    wcsncpy_s(pdi->item.pszText, pdi->item.cchTextMax, text.c_str(), _TRUNCATE);
    return 0;
}

std::wstring MainDlg::RowText(size_t filteredIndex) const {
    const auto& row = filtered_[filteredIndex];
    const auto& mods =
        row.mutated ? engine_->MutatedResults() : engine_->Results();
    const auto& mod = mods[row.module];
    const auto& g = mod.gadgets[row.gadget];
    const bool is64 = mod.arch != kArchX86 && mod.arch != kArchArm;

    std::wstring prefix = L"[" + util::ToWide(mod.moduleName) +
                          (row.mutated ? L":mutated]" : L"]") + L" ";
    return prefix + util::ToWide(util::FormatAddress(g.address, is64)) + L": " +
           util::ToWide(g.disassembly) + L" (" +
           std::to_wstring(g.numOccurrences) + L" found)";
}

void MainDlg::CopyTextToClipboard(const std::wstring& text) {
    if (!::OpenClipboard(m_hWnd))
        return;
    const size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL h = ::GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (h) {
        std::memcpy(::GlobalLock(h), text.c_str(), bytes);
        ::GlobalUnlock(h);
        ::EmptyClipboard();
        ::SetClipboardData(CF_UNICODETEXT, h);
    }
    ::CloseClipboard();
}

void MainDlg::CopyToClipboard(bool selectedOnly) {
    if (filtered_.empty())
        return;

    std::wstring text;
    size_t copied = 0;
    if (selectedOnly && list_.GetSelectedCount() > 0) {
        int item = list_.GetNextItem(-1, LVNI_SELECTED);
        while (item >= 0) {
            text += RowText(static_cast<size_t>(item));
            text += L"\r\n";
            ++copied;
            item = list_.GetNextItem(item, LVNI_SELECTED);
        }
    } else {
        for (size_t i = 0; i < filtered_.size(); ++i) {
            text += RowText(i);
            text += L"\r\n";
        }
        copied = filtered_.size();
    }
    CopyTextToClipboard(text);
    AppendLog("Copied " + std::to_string(copied) + " row(s) to clipboard.");
}

void MainDlg::OnCopy(UINT, int, CWindow) {
    CopyToClipboard(true);
}

// Ctrl+C: if the log edit has focus, let it copy its own selection;
// otherwise copy the selected gadget rows.
void MainDlg::CopyFocusedControl() {
    const HWND focus = ::GetFocus();
    if (focus != nullptr && focus == GetDlgItem(IDC_LOG)) {
        ::SendMessageW(focus, WM_COPY, 0, 0);
        return;
    }
    CopyToClipboard(true);
}

LRESULT MainDlg::OnListDoubleClick(NMHDR* pnmh) {
    auto* nm = reinterpret_cast<NMITEMACTIVATE*>(pnmh);
    if (nm->iItem >= 0 && static_cast<size_t>(nm->iItem) < filtered_.size()) {
        const std::wstring text = RowText(static_cast<size_t>(nm->iItem));
        CopyTextToClipboard(text);
        AppendLog("Copied: " + util::ToUtf8(text));
    }
    return 0;
}

LRESULT MainDlg::OnListRightClick(NMHDR*) {
    CMenu menu;
    menu.CreatePopupMenu();
    menu.AppendMenu(MF_STRING | (list_.GetSelectedCount() > 0 ? 0 : MF_GRAYED),
                    ID_EDIT_COPY_SEL, L"&Copy Selected\tCtrl+C");
    menu.AppendMenu(MF_STRING, ID_EDIT_COPY_ALL, L"Copy &All Filtered Rows");
    menu.AppendMenu(MF_SEPARATOR);
    menu.AppendMenu(MF_STRING, ID_TOOLS_OPEN_OUTPUT, L"&Open Output Folder");
    menu.SetMenuDefaultItem(ID_EDIT_COPY_SEL, FALSE);

    CPoint pt;
    ::GetCursorPos(&pt);
    const int cmd = menu.TrackPopupMenu(
        TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, m_hWnd);
    switch (cmd) {
    case ID_EDIT_COPY_SEL: CopyFocusedControl(); break;
    case ID_EDIT_COPY_ALL: CopyToClipboard(false); break;
    case ID_TOOLS_OPEN_OUTPUT: OpenOutputInExplorer(); break;
    default: break;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Menus / commands
// ---------------------------------------------------------------------------

void MainDlg::OnInitMenuPopup(CMenuHandle menu, UINT uPos, BOOL bSysMenu) {
    if (bSysMenu || menu.m_hMenu == nullptr)
        return;

    // Identify menus by handle: WM_INITMENUPOPUP also arrives for submenus
    // with positions relative to their parent.
    CMenu main = GetMenu();
    CMenuHandle file = main.GetSubMenu(0);
    CMenuHandle edit = main.GetSubMenu(1);
    CMenuHandle view = main.GetSubMenu(2);

    if (file.m_hMenu != nullptr && menu.m_hMenu == file.m_hMenu) {
        // Rebuild the Recent Folders submenu (item index 2 in File).
        CMenuHandle recent = file.GetSubMenu(2);
        if (recent.m_hMenu == nullptr)
            return;
        while (recent.GetMenuItemCount() > 0)
            recent.RemoveMenu(0, MF_BYPOSITION);
        if (settings_.mruFolders.empty()) {
            recent.AppendMenu(MF_STRING | MF_GRAYED, ID_MRU_FOLDER0,
                              L"(no recent folders)");
        } else {
            wchar_t label[MAX_PATH * 2 + 8];
            for (size_t i = 0; i < settings_.mruFolders.size() &&
                               i < Settings::kMaxMru; ++i) {
                swprintf_s(label, L"&%zu  %s", i + 1,
                           settings_.mruFolders[i].c_str());
                recent.AppendMenu(MF_STRING,
                                  ID_MRU_FOLDER0 + static_cast<UINT>(i),
                                  label);
            }
        }
        return;
    }

    if (edit.m_hMenu != nullptr && menu.m_hMenu == edit.m_hMenu) {
        menu.EnableMenuItem(ID_EDIT_COPY_SEL,
                            MF_BYCOMMAND |
                                (list_.GetSelectedCount() > 0 ? 0 : MF_GRAYED));
        menu.EnableMenuItem(ID_EDIT_COPY_ALL,
                            MF_BYCOMMAND | (filtered_.empty() ? MF_GRAYED : 0));
        return;
    }

    if (view.m_hMenu != nullptr && menu.m_hMenu == view.m_hMenu) {
        view.CheckMenuItem(ID_VIEW_GADGETS,
                           MF_BYCOMMAND | (activeTab_ == 0 ? MF_CHECKED : 0));
        view.CheckMenuItem(ID_VIEW_LOG,
                           MF_BYCOMMAND | (activeTab_ == 1 ? MF_CHECKED : 0));
    }
}

void MainDlg::OnMruFolder(UINT, int nID, CWindow) {
    const size_t idx = static_cast<size_t>(nID - ID_MRU_FOLDER0);
    if (idx < settings_.mruFolders.size())
        ::SetDlgItemTextW(m_hWnd, IDC_FOLDER_COMBO,
                          settings_.mruFolders[idx].c_str());
}

void MainDlg::OnMenuCopySelected(UINT, int, CWindow) {
    CopyFocusedControl();
}

void MainDlg::OnMenuCopyAll(UINT, int, CWindow) {
    CopyToClipboard(false);
}

void MainDlg::OnViewGadgets(UINT, int, CWindow) {
    tab_.SetCurSel(0);
    SetTab(0);
}

void MainDlg::OnViewLog(UINT, int, CWindow) {
    tab_.SetCurSel(1);
    SetTab(1);
}

void MainDlg::OpenOutputInExplorer() const {
    const std::wstring path = GetDlgItemWText(m_hWnd, IDC_OUTPUT_PATH);
    if (path.empty())
        return;
    // PerModule: open the directory. Single file: select it in Explorer.
    if (IsDlgButtonChecked(IDC_SPLIT) == BST_CHECKED) {
        ::ShellExecuteW(nullptr, L"open", L"explorer.exe", path.c_str(),
                        nullptr, SW_SHOWNORMAL);
    } else {
        const std::wstring args = L"/select,\"" + path + L"\"";
        ::ShellExecuteW(nullptr, L"open", L"explorer.exe", args.c_str(),
                        nullptr, SW_SHOWNORMAL);
    }
}

void MainDlg::OnOpenOutputFolder(UINT, int, CWindow) {
    OpenOutputInExplorer();
}

void MainDlg::ShowAboutBox() {
    CAboutTaskDialog dlg;
    int selected = 0;
    dlg.DoModal(m_hWnd, &selected);
}

void MainDlg::OnAbout(UINT, int, CWindow) {
    ShowAboutBox();
}

// ---------------------------------------------------------------------------
// Tabs / misc
// ---------------------------------------------------------------------------

LRESULT MainDlg::OnTabChanged(NMHDR*) {
    SetTab(tab_.GetCurSel());
    return 0;
}

void MainDlg::SetTab(int index) {
    activeTab_ = index;
    ShowPane(index);
}

void MainDlg::ShowPane(int index) {
    // Gadgets pane
    const BOOL gadgets = (index == 0);
    ::ShowWindow(GetDlgItem(IDC_FILTER_LBL), gadgets ? SW_SHOW : SW_HIDE);
    ::ShowWindow(GetDlgItem(IDC_FILTER), gadgets ? SW_SHOW : SW_HIDE);
    ::ShowWindow(GetDlgItem(IDC_MODULE_FILTER), gadgets ? SW_SHOW : SW_HIDE);
    ::ShowWindow(GetDlgItem(IDC_COPY), gadgets ? SW_SHOW : SW_HIDE);
    ::ShowWindow(GetDlgItem(IDC_RESULTS_COUNT), gadgets ? SW_SHOW : SW_HIDE);
    ::ShowWindow(GetDlgItem(IDC_LIST), gadgets ? SW_SHOW : SW_HIDE);
    ::ShowWindow(GetDlgItem(IDC_LOG), index == 1 ? SW_SHOW : SW_HIDE);
}

void MainDlg::OnToggleMutation(UINT, int, CWindow) {
    UpdateMutationState();
}

void MainDlg::UpdateMutationState() {
    const bool enabled =
        IsDlgButtonChecked(IDC_ENABLE_MUTATION) == BST_CHECKED;
    ::EnableWindow(GetDlgItem(IDC_MAX_MUTATION_OFFSET), enabled);
    ::EnableWindow(GetDlgItem(IDC_MUTATE_BRANCHES), enabled);
}

} // namespace gadgets
