#include "MainDlg.hpp"

#include <algorithm>
#include <filesystem>

#include "Core/Sink.hpp"
#include "Core/Util.hpp"
#include "Defaults.hpp"

namespace gadgets {

namespace {

std::wstring GetDlgItemWText(HWND dlg, int id) {
    int len = ::GetWindowTextLengthW(::GetDlgItem(dlg, id));
    std::wstring text(static_cast<size_t>(len) + 1, L'\0');
    int copied = ::GetDlgItemTextW(dlg, id, text.data(), len + 1);
    text.resize(static_cast<size_t>(copied));
    return text;
}

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

    CenterWindow();

    CRect rc;
    GetWindowRect(&rc);
    minSize_ = { rc.Width(), rc.Height() };

    DlgResize_Init(true, true, 0);

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
    list_.AddColumn(L"#", 5);
    list_.SetColumnWidth(0, 44);
    list_.SetColumnWidth(1, 110);
    list_.SetColumnWidth(2, 150);
    list_.SetColumnWidth(3, 380);
    list_.SetColumnWidth(4, 160);
    list_.SetColumnWidth(5, 40);

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

    monoFont_.CreateFont(
        kMonoFontSize, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, kMonoFontName);
    CEdit logCtrl(GetDlgItem(IDC_LOG));
    logCtrl.SetFont(monoFont_);
    CEdit filterCtrl(GetDlgItem(IDC_FILTER));
    filterCtrl.SetFont(monoFont_);

    // Defaults
    SetDlgItemInt(IDC_MAX_GADGET_LEN, 5, FALSE);
    SetDlgItemInt(IDC_MAX_THREADS, Engine::DefaultThreads(), FALSE);
    SetDlgItemInt(IDC_MAX_MUTATION_OFFSET, kDefaultMutationLookback, FALSE);

    settings_.Load();
    LoadSettingsToUi();

    SetTab(0);
    UpdateMutationState();

    SetDlgItemTextA(m_hWnd, IDC_ELAPSED, "");
    SetDlgItemTextA(m_hWnd, IDC_ETA, "");
    SetDlgItemTextA(m_hWnd, IDC_GADGET_COUNT, "");

    return TRUE;
}
void MainDlg::OnDestroy() {
    KillTimer(kUiTimerId);
    if (worker_.joinable())
        worker_.join();
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

void MainDlg::OnTimer(UINT_PTR timerId) {
    if (timerId != kUiTimerId || !scanning_.load())
        return;
    UpdateUiFromSnapshot();
    DrainLog();
}

void MainDlg::UpdateUiFromSnapshot() {
    if (!engine_)
        return;

    const auto snap = engine_->Snapshot();

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
    progressBar_.SetPos(pct);

    std::wstring status;
    switch (snap.phase) {
    case Phase::Enumerating: status = L"Enumerating..."; break;
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
        ::SetDlgItemTextW(m_hWnd, IDC_STATUS, status.c_str());

    const auto elapsed = std::chrono::duration<double>(
                             std::chrono::steady_clock::now() - scanStart_)
                             .count();
    SetDlgItemTextA(m_hWnd, IDC_ELAPSED,
                    util::FormatElapsed(elapsed).c_str());

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
    ::SetDlgItemTextW(m_hWnd, IDC_ETA, (L"ETA " + eta).c_str());

    wchar_t count[96];
    swprintf_s(count, L"%zu gadgets%s", snap.gadgetsFound,
               snap.mutatedFound > 0
                   ? (L" +" + std::to_wstring(snap.mutatedFound) + L" mut").c_str()
                   : L"");
    ::SetDlgItemTextW(m_hWnd, IDC_GADGET_COUNT, count);
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
    ::SetDlgItemTextW(m_hWnd, IDC_STATUS, L"Starting...");
    SetDlgItemTextA(m_hWnd, IDC_ELAPSED, "");
    SetDlgItemTextA(m_hWnd, IDC_ETA, "");
    SetDlgItemTextA(m_hWnd, IDC_GADGET_COUNT, "");
    progressBar_.SetPos(0);
    rows_.clear();
    filtered_.clear();
    list_.SetItemCount(0);
    moduleCombo_.ResetContent();
    moduleCombo_.AddString(L"All modules");
    moduleCombo_.SetCurSel(0);
    moduleCombo_.EnableWindow(FALSE);
    SetDlgItemTextA(m_hWnd, IDC_RESULTS_COUNT, "");

    scanning_.store(true);
    stop_.Reset();
    scanStart_ = std::chrono::steady_clock::now();

    ::SetDlgItemTextW(m_hWnd, IDC_SCAN, L"Cancel");
    ::EnableWindow(GetDlgItem(IDC_ENABLE_MUTATION), FALSE);

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
    progressBar_.SetPos(stats->cancelled ? progressBar_.GetPos() : 100);

    ::SetDlgItemTextW(m_hWnd, IDC_SCAN, L"Scan");
    ::EnableWindow(GetDlgItem(IDC_SCAN), TRUE);
    ::EnableWindow(GetDlgItem(IDC_ENABLE_MUTATION), TRUE);

    wchar_t status[128];
    if (stats->cancelled) {
        swprintf_s(status, L"Cancelled - %u module(s) scanned",
                   stats->filesScanned);
    } else if (stats->filesFailed > 0 || !stats->outputWritten) {
        swprintf_s(status, L"Finished with errors (%u failed)",
                   stats->filesFailed);
    } else {
        swprintf_s(status, L"Done - %u module(s), %zu gadgets",
                   stats->filesScanned, stats->gadgetsFound);
    }
    ::SetDlgItemTextW(m_hWnd, IDC_STATUS, status);
    SetDlgItemTextA(m_hWnd, IDC_ETA, "");

    BuildRows();
    ApplyFilter();
    moduleCombo_.EnableWindow(moduleCombo_.GetCount() > 1);

    ::MessageBeep(stats->cancelled ? MB_ICONEXCLAMATION : MB_ICONASTERISK);
    return 0;
}

void MainDlg::OnCancel(UINT, int nID, CWindow) {
    if (scanning_.load()) {
        CancelScan();
        return;
    }
    SaveSettingsFromUi();
    EndDialog(nID);
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

    list_.SetItemCount(static_cast<int>(filtered_.size()));

    wchar_t count[96];
    swprintf_s(count, L"%zu / %zu rows", filtered_.size(), rows_.size());
    ::SetDlgItemTextW(m_hWnd, IDC_RESULTS_COUNT, count);
}

LRESULT MainDlg::OnFilterChanged(WORD, WORD, HWND) {
    ApplyFilter();
    return 0;
}

LRESULT MainDlg::OnModuleFilterChanged(WORD, WORD, HWND) {
    ApplyFilter();
    return 0;
}

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

void MainDlg::CopyToClipboard(bool selectedOnly) {
    if (filtered_.empty() || !::OpenClipboard(m_hWnd))
        return;

    std::wstring text;
    if (selectedOnly && list_.GetSelectedCount() > 0) {
        int item = list_.GetNextItem(-1, LVNI_SELECTED);
        while (item >= 0) {
            text += RowText(static_cast<size_t>(item));
            text += L"\r\n";
            item = list_.GetNextItem(item, LVNI_SELECTED);
        }
    } else {
        for (size_t i = 0; i < filtered_.size(); ++i) {
            text += RowText(i);
            text += L"\r\n";
        }
    }

    const size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL h = ::GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (h) {
        std::memcpy(::GlobalLock(h), text.c_str(), bytes);
        ::GlobalUnlock(h);
        ::EmptyClipboard();
        ::SetClipboardData(CF_UNICODETEXT, h);
    }
    ::CloseClipboard();

    AppendLog("Copied " + std::to_string(
        selectedOnly && list_.GetSelectedCount() > 0
            ? static_cast<size_t>(list_.GetSelectedCount())
            : filtered_.size()) + " row(s) to clipboard.");
}

void MainDlg::OnCopy(UINT, int, CWindow) {
    CopyToClipboard(true);
}

LRESULT MainDlg::OnListKeyDown(NMHDR* pnmh) {
    auto* lv = reinterpret_cast<NMLVKEYDOWN*>(pnmh);
    if (lv->wVKey == 'C' && (::GetKeyState(VK_CONTROL) & 0x8000)) {
        CopyToClipboard(true);
        return 1;
    }
    return 0;
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
    ::ShowWindow(GetDlgItem(IDC_FILTER), gadgets ? SW_SHOW : SW_HIDE);
    ::ShowWindow(GetDlgItem(IDC_MODULE_FILTER), gadgets ? SW_SHOW : SW_HIDE);
    ::ShowWindow(GetDlgItem(IDC_COPY), gadgets ? SW_SHOW : SW_HIDE);
    ::ShowWindow(GetDlgItem(IDC_RESULTS_COUNT), gadgets ? SW_SHOW : SW_HIDE);
    ::ShowWindow(GetDlgItem(IDC_LIST), gadgets ? SW_SHOW : SW_HIDE);
    // Label above the filter edit ("Filter:")
    ::ShowWindow(::GetWindow(GetDlgItem(IDC_FILTER), GW_HWNDPREV),
                 gadgets ? SW_SHOW : SW_HIDE);
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
