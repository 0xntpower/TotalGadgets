#include "MainDlg.hpp"

#include <algorithm>
#include <charconv>
#include <filesystem>
#include <sstream>

#include <atlscrl.h>

#include "Defaults.hpp"
#include "Mutator.hpp"

namespace gadgets {

namespace {

std::string GetDlgItemString(HWND dlg, int id) {
    char buf[1024] = {};
    ::GetDlgItemTextA(dlg, id, buf, sizeof(buf));
    return buf;
}

std::vector<uint8_t> ParseBadBytes(const std::string& input) {
    std::vector<uint8_t> result;
    std::istringstream stream(input);
    std::string token;
    while (stream >> token) {
        try {
            auto val = std::stoul(token, nullptr, 16);
            if (val <= 0xFF)
                result.push_back(static_cast<uint8_t>(val));
        } catch (...) {}
    }
    return result;
}

void SetCueBanner(HWND dlg, int id, const wchar_t* text) {
    ::SendDlgItemMessageW(dlg, id, EM_SETCUEBANNER, TRUE,
                          reinterpret_cast<LPARAM>(text));
}

} // namespace

BOOL MainDlg::OnInitDialog(CWindow /*wndFocus*/, LPARAM /*lInitParam*/) {
    // Window icon
    HICON hIcon = AtlLoadIconImage(IDR_MAINFRAME, LR_DEFAULTCOLOR,
                                   ::GetSystemMetrics(SM_CXICON),
                                   ::GetSystemMetrics(SM_CYICON));
    SetIcon(hIcon, TRUE);
    HICON hIconSmall = AtlLoadIconImage(IDR_MAINFRAME, LR_DEFAULTCOLOR,
                                        ::GetSystemMetrics(SM_CXSMICON),
                                        ::GetSystemMetrics(SM_CYSMICON));
    SetIcon(hIconSmall, FALSE);

    CenterWindow();

    // Store initial size as minimum
    CRect rc;
    GetWindowRect(&rc);
    minSize_ = { rc.Width(), rc.Height() };

    // Init resize
    DlgResize_Init(true, true, 0);

    // Progress bar
    progressBar_ = GetDlgItem(IDC_PROGRESS);
    progressBar_.SetRange(0, 100);
    progressBar_.SetPos(0);

    // Monospace font for log
    logFont_.CreateFont(
        kLogFontSize, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, kLogFontName);
    CEdit logCtrl(GetDlgItem(IDC_LOG));
    logCtrl.SetFont(logFont_);

    // Defaults
    SetDlgItemInt(IDC_MAX_GADGET_LEN, kDefaultMaxGadgetLen, FALSE);
    SetDlgItemInt(IDC_MAX_THREADS, kDefaultMaxThreads, FALSE);
    SetDlgItemInt(IDC_MAX_MUTATION_OFFSET, kDefaultMutationOffset, FALSE);

    // Cue banners
    SetCueBanner(m_hWnd, IDC_FOLDER_PATH, L"Select folder containing PE binaries...");
    SetCueBanner(m_hWnd, IDC_OUTPUT_PATH, L"Choose output file path...");
    SetCueBanner(m_hWnd, IDC_BAD_BYTES, L"e.g. 00 0a 0d");

    // Mutation controls start disabled
    UpdateMutationState();

    // Status labels
    SetDlgItemTextA(m_hWnd, IDC_ELAPSED, "");
    SetDlgItemTextA(m_hWnd, IDC_GADGET_COUNT, "");

    return TRUE;
}

void MainDlg::OnDestroy() {
    KillTimer(kTimerId);
    if (workerThread_.joinable())
        workerThread_.join();
}

void MainDlg::OnTimer(UINT_PTR timerId) {
    if (timerId == kTimerId && scanning_)
        UpdateElapsed();
}

void MainDlg::OnGetMinMaxInfo(LPMINMAXINFO mmi) {
    if (minSize_.cx > 0) {
        mmi->ptMinTrackSize.x = minSize_.cx;
        mmi->ptMinTrackSize.y = minSize_.cy;
    }
}

void MainDlg::OnBrowseFolder(UINT, int, CWindow) {
    CFolderDialog dlg(m_hWnd, _T("Select folder containing PE files"));
    if (dlg.DoModal() == IDOK)
        SetDlgItemText(IDC_FOLDER_PATH, dlg.GetFolderPath());
}

void MainDlg::OnBrowseOutput(UINT, int, CWindow) {
    CFileDialog dlg(FALSE, _T("txt"), _T("gadgets.txt"),
                    OFN_OVERWRITEPROMPT,
                    _T("Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0"));
    if (dlg.DoModal() == IDOK)
        SetDlgItemText(IDC_OUTPUT_PATH, dlg.m_szFileName);
}

void MainDlg::OnScan(UINT, int, CWindow) {
    if (scanning_)
        return;

    auto folder = GetDlgItemString(m_hWnd, IDC_FOLDER_PATH);
    auto output = GetDlgItemString(m_hWnd, IDC_OUTPUT_PATH);

    if (folder.empty() || output.empty()) {
        ::MessageBoxA(m_hWnd, "Please specify both a PE folder and output file path.",
                      "Total Gadgets", MB_OK | MB_ICONWARNING);
        return;
    }

    if (!std::filesystem::is_directory(folder)) {
        ::MessageBoxA(m_hWnd, "The specified folder does not exist.",
                      "Total Gadgets", MB_OK | MB_ICONERROR);
        return;
    }

    scanning_ = true;
    scanStart_ = std::chrono::steady_clock::now();

    ::EnableWindow(GetDlgItem(IDC_SCAN), FALSE);
    SetDlgItemTextA(m_hWnd, IDC_SCAN, "Scanning...");

    // Clear state
    SetDlgItemText(IDC_LOG, _T(""));
    SetDlgItemTextA(m_hWnd, IDC_GADGET_COUNT, "");
    SetDlgItemTextA(m_hWnd, IDC_ELAPSED, "");
    progressBar_.SetPos(0);

    SetTimer(kTimerId, kElapsedTimerIntervalMs);

    if (workerThread_.joinable())
        workerThread_.join();

    workerThread_ = std::thread([this] { RunScan(); });
}

void MainDlg::OnToggleMutation(UINT, int, CWindow) {
    UpdateMutationState();
}

void MainDlg::OnCancel(UINT, int nID, CWindow) {
    if (scanning_) {
        ::MessageBoxA(m_hWnd, "A scan is in progress. Please wait for it to complete.",
                      "Total Gadgets", MB_OK | MB_ICONINFORMATION);
        return;
    }
    if (workerThread_.joinable())
        workerThread_.join();
    EndDialog(nID);
}

LRESULT MainDlg::OnScanLog(UINT, WPARAM wParam, LPARAM) {
    auto* msg = reinterpret_cast<std::string*>(wParam);
    AppendLog(*msg);
    delete msg;
    return 0;
}

LRESULT MainDlg::OnScanProgress(UINT, WPARAM wParam, LPARAM lParam) {
    auto* status = reinterpret_cast<std::string*>(wParam);
    int percent = static_cast<int>(lParam);
    progressBar_.SetPos(percent);
    SetDlgItemTextA(m_hWnd, IDC_STATUS, status->c_str());
    delete status;
    return 0;
}

LRESULT MainDlg::OnScanDone(UINT, WPARAM wParam, LPARAM) {
    KillTimer(kTimerId);
    UpdateElapsed();

    auto totalGadgets = static_cast<size_t>(wParam);
    if (totalGadgets > 0) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%zu gadgets", totalGadgets);
        SetDlgItemTextA(m_hWnd, IDC_GADGET_COUNT, buf);
    }

    progressBar_.SetPos(100);
    SetDlgItemTextA(m_hWnd, IDC_STATUS, "Done");
    SetDlgItemTextA(m_hWnd, IDC_SCAN, "Scan");
    ::EnableWindow(GetDlgItem(IDC_SCAN), TRUE);
    scanning_ = false;

    ::MessageBeep(MB_ICONINFORMATION);
    return 0;
}

void MainDlg::AppendLog(const std::string& text) {
    CEdit logCtrl(GetDlgItem(IDC_LOG));
    int len = logCtrl.GetWindowTextLength();
    logCtrl.SetSel(len, len);

    std::string line = text + "\r\n";
    logCtrl.ReplaceSel(CString(line.c_str()));
}

void MainDlg::UpdateMutationState() {
    bool enabled = (IsDlgButtonChecked(IDC_ENABLE_MUTATION) == BST_CHECKED);
    ::EnableWindow(GetDlgItem(IDC_MAX_MUTATION_OFFSET), enabled);
}

void MainDlg::UpdateElapsed() {
    auto now = std::chrono::steady_clock::now();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
        now - scanStart_).count();

    char buf[32];
    if (seconds < 60)
        std::snprintf(buf, sizeof(buf), "%llds", seconds);
    else
        std::snprintf(buf, sizeof(buf), "%lldm %02llds", seconds / 60, seconds % 60);

    SetDlgItemTextA(m_hWnd, IDC_ELAPSED, buf);
}

librp::SearchOptions MainDlg::BuildSearchOptions() {
    librp::SearchOptions opts;
    opts.maxGadgetLen = GetDlgItemInt(IDC_MAX_GADGET_LEN, nullptr, FALSE);
    opts.maxThreads = GetDlgItemInt(IDC_MAX_THREADS, nullptr, FALSE);
    opts.uniqueOnly = (IsDlgButtonChecked(IDC_UNIQUE_ONLY) == BST_CHECKED);
    opts.allowBranches = (IsDlgButtonChecked(IDC_ALLOW_BRANCHES) == BST_CHECKED);

    auto badBytesStr = GetDlgItemString(m_hWnd, IDC_BAD_BYTES);
    opts.badBytes = ParseBadBytes(badBytesStr);

    if (opts.maxGadgetLen == 0) opts.maxGadgetLen = kDefaultMaxGadgetLen;
    if (opts.maxThreads == 0) opts.maxThreads = kDefaultMaxThreads;

    return opts;
}

ScanConfig MainDlg::BuildScanConfig() {
    ScanConfig config;
    config.folderPath = GetDlgItemString(m_hWnd, IDC_FOLDER_PATH);
    config.outputPath = GetDlgItemString(m_hWnd, IDC_OUTPUT_PATH);
    config.searchOptions = BuildSearchOptions();
    config.includeSubfolders = (IsDlgButtonChecked(IDC_INCLUDE_SUBFOLDERS) == BST_CHECKED);
    return config;
}

void MainDlg::RunScan() {
    auto config = BuildScanConfig();
    HWND hwnd = m_hWnd;

    auto postLog = [hwnd](const std::string& msg) {
        auto* copy = new std::string(msg);
        ::PostMessage(hwnd, WM_SCAN_LOG, reinterpret_cast<WPARAM>(copy), 0);
    };

    auto postProgress = [hwnd](const std::string& status, int current, int total) {
        int percent = (total > 0) ? (current * 100 / total) : 0;
        auto* copy = new std::string(status);
        ::PostMessage(hwnd, WM_SCAN_PROGRESS, reinterpret_cast<WPARAM>(copy), percent);
    };

    postLog("Starting scan...");

    auto results = ScanFolder(config, postProgress, postLog);

    size_t totalGadgets = 0;
    for (const auto& mod : results)
        totalGadgets += mod.gadgets.size();

    postLog("Writing output: " + config.outputPath.string());
    WriteGadgetFile(config.outputPath, results);
    postLog("Total: " + std::to_string(totalGadgets) + " gadgets from " +
            std::to_string(results.size()) + " module(s).");

    // Mutation pass
    bool mutationEnabled = (::SendDlgItemMessage(hwnd, IDC_ENABLE_MUTATION,
                                                  BM_GETCHECK, 0, 0) == BST_CHECKED);
    if (mutationEnabled && !results.empty()) {
        postLog("");
        postLog("Starting gadget mutation pass...");

        MutationConfig mutConfig;
        mutConfig.maxOffset = ::GetDlgItemInt(hwnd, IDC_MAX_MUTATION_OFFSET, nullptr, FALSE);
        mutConfig.maxGadgetLen = config.searchOptions.maxGadgetLen;
        mutConfig.badBytes = config.searchOptions.badBytes;

        if (mutConfig.maxOffset < kMinMutationOffset) mutConfig.maxOffset = kDefaultMutationOffset;
        if (mutConfig.maxOffset > kMaxMutationOffset) mutConfig.maxOffset = kMaxMutationOffset;

        auto mutated = MutateGadgets(results, mutConfig, postProgress, postLog);

        if (!mutated.empty()) {
            auto mutPath = config.outputPath;
            auto stem = mutPath.stem().string();
            auto ext = mutPath.extension().string();
            mutPath.replace_filename(stem + "_mutated" + ext);

            postLog("Writing mutated gadgets: " + mutPath.string());
            WriteGadgetFile(mutPath, mutated, true);

            size_t mutTotal = 0;
            for (const auto& mod : mutated)
                mutTotal += mod.gadgets.size();
            totalGadgets += mutTotal;
            postLog("Mutation complete: " + std::to_string(mutTotal) +
                    " new gadgets discovered.");
        } else {
            postLog("Mutation complete: no new gadgets found.");
        }
    }

    postLog("");
    postLog("Done.");
    ::PostMessage(hwnd, WM_SCAN_DONE, static_cast<WPARAM>(totalGadgets), 0);
}

} // namespace gadgets
