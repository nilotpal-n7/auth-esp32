// =============================================================================
// AuthKeyProvider.cpp — Windows credential provider for the AuthKey-ESP32
//
// Adds an "AuthKey" sign-in option to the lock screen / sign-in screen (and
// credential prompts). When the tile is selected it asks the AuthKeyUnlock
// service (named pipe) to verify the device; on success the service returns
// the stored Windows credentials and this provider signs in automatically.
//
// Safety:
//  * If the service is not running / not paired, or the file
//    %ProgramData%\AuthKey\disabled exists, the provider shows nothing.
//  * After Windows rejects the stored password once, automatic sign-in stops
//    for the rest of that screen session (no account-lockout loops).
//  * It never filters or hides the other providers (PIN, password, face).
// =============================================================================

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <windows.h>
#include <unknwn.h>
#include <credentialprovider.h>
#include <ntsecapi.h>
#define SECURITY_WIN32
#include <security.h>
#include <wincred.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <strsafe.h>
#include <new>
#include <string>

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#endif

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

// {50B5E277-5F97-43F5-AE3C-3542AD8DF74C}
static const CLSID CLSID_AuthKeyProvider =
    {0x50b5e277, 0x5f97, 0x43f5, {0xae, 0x3c, 0x35, 0x42, 0xad, 0x8d, 0xf7, 0x4c}};

static LONG g_dllRefs = 0;
static HINSTANCE g_hinst = nullptr;
static void DllAddRef() { InterlockedIncrement(&g_dllRefs); }
static void DllRelease() { InterlockedDecrement(&g_dllRefs); }

// --- Fields ------------------------------------------------------------------

enum FieldId { FI_TILEIMAGE = 0, FI_LABEL, FI_STATUS, FI_SUBMIT, FI_NUM_FIELDS };

static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_fields[FI_NUM_FIELDS] = {
    {FI_TILEIMAGE, CPFT_TILE_IMAGE, const_cast<PWSTR>(L"Image"), CPFG_CREDENTIAL_PROVIDER_LOGO},
    {FI_LABEL, CPFT_LARGE_TEXT, const_cast<PWSTR>(L"AuthKey"), CPFG_CREDENTIAL_PROVIDER_LABEL},
    {FI_STATUS, CPFT_SMALL_TEXT, const_cast<PWSTR>(L"Status"), GUID_NULL},
    {FI_SUBMIT, CPFT_SUBMIT_BUTTON, const_cast<PWSTR>(L"Submit"), GUID_NULL},
};

static const CREDENTIAL_PROVIDER_FIELD_STATE s_fieldStates[FI_NUM_FIELDS] = {
    CPFS_DISPLAY_IN_BOTH, CPFS_DISPLAY_IN_BOTH, CPFS_DISPLAY_IN_SELECTED_TILE, CPFS_DISPLAY_IN_SELECTED_TILE,
};

// --- Helpers -------------------------------------------------------------------

static std::wstring ProgramDataPath(const wchar_t* leaf) {
    wchar_t* base = nullptr;
    std::wstring path;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &base))) {
        path = base;
        path += L"\\AuthKey\\";
        path += leaf;
    }
    CoTaskMemFree(base);
    return path;
}

static bool IsDisabled() {
    std::wstring p = ProgramDataPath(L"disabled");
    return !p.empty() && GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES;
}

static void SecureWipe(std::wstring& s) {
    if (!s.empty()) SecureZeroMemory(&s[0], s.size() * sizeof(wchar_t));
    s.clear();
}

static std::wstring FromB64(const char* b64, size_t len) {
    DWORD cb = 0;
    if (!CryptStringToBinaryA(b64, (DWORD)len, CRYPT_STRING_BASE64, nullptr, &cb, nullptr, nullptr)) return L"";
    std::string bytes(cb, '\0');
    if (!CryptStringToBinaryA(b64, (DWORD)len, CRYPT_STRING_BASE64, (BYTE*)&bytes[0], &cb, nullptr, nullptr)) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, bytes.data(), (int)cb, nullptr, 0);
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, bytes.data(), (int)cb, &out[0], n);
    SecureZeroMemory(&bytes[0], bytes.size());
    return out;
}

// One request/response over the service pipe. Returns false if unavailable.
static bool PipeRequest(const char* request, std::string& reply, DWORD connectTimeoutMs) {
    reply.clear();
    const wchar_t* name = L"\\\\.\\pipe\\AuthKeyUnlock";
    HANDLE h = INVALID_HANDLE_VALUE;
    DWORD start = GetTickCount();
    for (;;) {
        h = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_PIPE_BUSY || GetTickCount() - start > connectTimeoutMs) return false;
        WaitNamedPipeW(name, 500);
    }
    DWORD written = 0;
    std::string req = std::string(request) + "\n";
    bool ok = WriteFile(h, req.data(), (DWORD)req.size(), &written, nullptr) != FALSE;
    char buf[1024];
    while (ok) {
        DWORD read = 0;
        if (!ReadFile(h, buf, sizeof(buf), &read, nullptr) || read == 0) break;
        reply.append(buf, read);
        if (reply.find('\n') != std::string::npos) break;
        if (reply.size() > 8192) break;
    }
    SecureZeroMemory(buf, sizeof(buf));
    CloseHandle(h);
    size_t nl = reply.find('\n');
    if (nl != std::string::npos) reply.resize(nl);
    return !reply.empty();
}

// Split "TAG a b c" into up to 4 tokens.
static int Tokens(const std::string& s, std::string out[4]) {
    int n = 0;
    size_t pos = 0;
    while (n < 4 && pos < s.size()) {
        size_t sp = s.find(' ', pos);
        if (sp == std::string::npos) sp = s.size();
        out[n++] = s.substr(pos, sp - pos);
        pos = sp + 1;
    }
    return n;
}

static HRESULT UnicodeStringInit(PCWSTR s, UNICODE_STRING* us) {
    size_t len = 0;
    HRESULT hr = StringCchLengthW(s, USHRT_MAX / sizeof(wchar_t), &len);
    if (FAILED(hr)) return hr;
    us->Buffer = const_cast<PWSTR>(s);
    us->Length = (USHORT)(len * sizeof(wchar_t));
    us->MaximumLength = us->Length;
    return S_OK;
}

static void PackString(const UNICODE_STRING& src, PWSTR bufferStart, BYTE*& cursor, UNICODE_STRING* dst) {
    dst->Length = dst->MaximumLength = src.Length;
    memcpy(cursor, src.Buffer, src.Length);
    // Inside a serialized logon buffer, Buffer holds the offset from the start.
    dst->Buffer = (PWSTR)(cursor - (BYTE*)bufferStart);
    cursor += src.Length;
}

static HRESULT PackLogon(PCWSTR domain, PCWSTR user, PCWSTR password, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                         BYTE** out, DWORD* outLen) {
    KERB_INTERACTIVE_UNLOCK_LOGON kiul = {};
    KERB_INTERACTIVE_LOGON* kil = &kiul.Logon;
    HRESULT hr;
    if (FAILED(hr = UnicodeStringInit(domain, &kil->LogonDomainName))) return hr;
    if (FAILED(hr = UnicodeStringInit(user, &kil->UserName))) return hr;
    if (FAILED(hr = UnicodeStringInit(password, &kil->Password))) return hr;
    kil->MessageType = cpus == CPUS_UNLOCK_WORKSTATION ? KerbWorkstationUnlockLogon : KerbInteractiveLogon;

    DWORD cb = sizeof(kiul) + kil->LogonDomainName.Length + kil->UserName.Length + kil->Password.Length;
    BYTE* buf = (BYTE*)CoTaskMemAlloc(cb);
    if (!buf) return E_OUTOFMEMORY;
    KERB_INTERACTIVE_UNLOCK_LOGON* packed = (KERB_INTERACTIVE_UNLOCK_LOGON*)buf;
    packed->Logon.MessageType = kil->MessageType;
    packed->LogonId = kiul.LogonId;
    BYTE* cursor = buf + sizeof(kiul);
    PackString(kil->LogonDomainName, (PWSTR)buf, cursor, &packed->Logon.LogonDomainName);
    PackString(kil->UserName, (PWSTR)buf, cursor, &packed->Logon.UserName);
    PackString(kil->Password, (PWSTR)buf, cursor, &packed->Logon.Password);
    *out = buf;
    *outLen = cb;
    return S_OK;
}

static HRESULT NegotiatePackage(ULONG* pkg) {
    HANDLE lsa;
    if (LsaConnectUntrusted(&lsa) != STATUS_SUCCESS) return E_FAIL;
    LSA_STRING name;
    name.Buffer = const_cast<PCHAR>(NEGOSSP_NAME_A);
    name.Length = (USHORT)strlen(name.Buffer);
    name.MaximumLength = name.Length + 1;
    NTSTATUS st = LsaLookupAuthenticationPackage(lsa, &name, pkg);
    LsaDeregisterLogonProcess(lsa);
    return st == STATUS_SUCCESS ? S_OK : E_FAIL;
}

static HBITMAP MakeTileBitmap() {
    const int size = 192;
    BITMAPINFO bi = {};
    bi.bmiHeader.biSize = sizeof(bi.bmiHeader);
    bi.bmiHeader.biWidth = size;
    bi.bmiHeader.biHeight = -size;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    void* bits = nullptr;
    HDC screen = GetDC(nullptr);
    HBITMAP bmp = CreateDIBSection(screen, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    HDC dc = CreateCompatibleDC(screen);
    ReleaseDC(nullptr, screen);
    if (!bmp || !dc) {
        if (dc) DeleteDC(dc);
        return bmp;
    }
    HGDIOBJ old = SelectObject(dc, bmp);
    RECT r = {0, 0, size, size};
    HBRUSH bg = CreateSolidBrush(RGB(13, 71, 161));
    FillRect(dc, &r, bg);
    DeleteObject(bg);
    HFONT font = CreateFontW(-80, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY,
                             0, L"Segoe UI");
    HGDIOBJ oldFont = SelectObject(dc, font);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(255, 255, 255));
    DrawTextW(dc, L"AK", -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(dc, oldFont);
    DeleteObject(font);
    SelectObject(dc, old);
    DeleteDC(dc);
    return bmp;
}

// --- Credential ------------------------------------------------------------------

class Provider;

class Credential : public ICredentialProviderCredential2 {
public:
    Credential(Provider* provider, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, const std::wstring& sid);

    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&m_refs); }
    IFACEMETHODIMP_(ULONG) Release() override {
        LONG r = InterlockedDecrement(&m_refs);
        if (!r) delete this;
        return r;
    }
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_INVALIDARG;
        if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredential ||
            riid == IID_ICredentialProviderCredential2) {
            *ppv = static_cast<ICredentialProviderCredential2*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* events) override;
    IFACEMETHODIMP UnAdvise() override;
    IFACEMETHODIMP SetSelected(BOOL* autoLogon) override;
    IFACEMETHODIMP SetDeselected() override;
    IFACEMETHODIMP GetFieldState(DWORD id, CREDENTIAL_PROVIDER_FIELD_STATE* state,
                                 CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* istate) override;
    IFACEMETHODIMP GetStringValue(DWORD id, PWSTR* value) override;
    IFACEMETHODIMP GetBitmapValue(DWORD id, HBITMAP* bmp) override;
    IFACEMETHODIMP GetCheckboxValue(DWORD, BOOL*, PWSTR*) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetSubmitButtonValue(DWORD id, DWORD* adjacent) override;
    IFACEMETHODIMP GetComboBoxValueCount(DWORD, DWORD*, DWORD*) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetComboBoxValueAt(DWORD, DWORD, PWSTR*) override { return E_NOTIMPL; }
    IFACEMETHODIMP SetStringValue(DWORD, PCWSTR) override { return E_NOTIMPL; }
    IFACEMETHODIMP SetCheckboxValue(DWORD, BOOL) override { return E_NOTIMPL; }
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD, DWORD) override { return E_NOTIMPL; }
    IFACEMETHODIMP CommandLinkClicked(DWORD) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* resp,
                                    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* cs, PWSTR* statusText,
                                    CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) override;
    IFACEMETHODIMP ReportResult(NTSTATUS status, NTSTATUS substatus, PWSTR* statusText,
                                CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) override;
    // ICredentialProviderCredential2
    IFACEMETHODIMP GetUserSid(PWSTR* sid) override;

    bool Ready() const { return m_ready; }
    void Shutdown();

private:
    ~Credential();
    static DWORD WINAPI PollThread(void* self);
    bool TryUnlock();               // one blocking attempt via the service
    void SetStatus(PCWSTR text);

    LONG m_refs = 1;
    Provider* m_provider;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO m_cpus;
    std::wstring m_sid, m_domain, m_user, m_password, m_status;
    ICredentialProviderCredentialEvents* m_events = nullptr;
    CRITICAL_SECTION m_lock;
    volatile bool m_ready = false;
    volatile bool m_stop = false;
    volatile bool m_polling = false;
    volatile bool m_failed = false;   // Windows rejected the stored password
};

// --- Provider ----------------------------------------------------------------------

class Provider : public ICredentialProvider, public ICredentialProviderSetUserArray {
public:
    Provider() {
        DllAddRef();
        InitializeCriticalSection(&m_lock);
    }

    IFACEMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&m_refs); }
    IFACEMETHODIMP_(ULONG) Release() override {
        LONG r = InterlockedDecrement(&m_refs);
        if (!r) delete this;
        return r;
    }
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_INVALIDARG;
        if (riid == IID_IUnknown || riid == IID_ICredentialProvider) {
            *ppv = static_cast<ICredentialProvider*>(this);
        } else if (riid == IID_ICredentialProviderSetUserArray) {
            *ppv = static_cast<ICredentialProviderSetUserArray*>(this);
        } else {
            *ppv = nullptr;
            return E_NOINTERFACE;
        }
        AddRef();
        return S_OK;
    }

    // ICredentialProvider
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD flags) override {
        switch (cpus) {
            case CPUS_LOGON:
            case CPUS_UNLOCK_WORKSTATION:
                break;
            case CPUS_CREDUI:
                // 32-bit callers on 64-bit Windows need a different packing.
                if (flags & CREDUIWIN_PACK_32_WOW) return E_NOTIMPL;
                break;
            default:
                return E_NOTIMPL;
        }
        if (m_credential) return E_UNEXPECTED;   // scenario is set once per instance
        if (IsDisabled()) return E_NOTIMPL;
        // Only show the tile when the service is running and paired.
        std::string reply, tok[4];
        if (!PipeRequest("INFO", reply, 1500) || Tokens(reply, tok) < 3 || tok[0] != "INFO") return E_NOTIMPL;
        std::wstring sid = FromB64(tok[1].data(), tok[1].size());
        if (sid.empty()) return E_NOTIMPL;
        m_cpus = cpus;
        m_credential = new (std::nothrow) Credential(this, cpus, sid);
        return m_credential ? S_OK : E_OUTOFMEMORY;
    }
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) override { return E_NOTIMPL; }
    IFACEMETHODIMP Advise(ICredentialProviderEvents* events, UINT_PTR context) override {
        EnterCriticalSection(&m_lock);
        if (m_events) m_events->Release();
        m_events = events;
        if (m_events) m_events->AddRef();
        m_context = context;
        LeaveCriticalSection(&m_lock);
        return S_OK;
    }
    IFACEMETHODIMP UnAdvise() override {
        EnterCriticalSection(&m_lock);
        if (m_events) m_events->Release();
        m_events = nullptr;
        LeaveCriticalSection(&m_lock);
        return S_OK;
    }
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* count) override {
        *count = FI_NUM_FIELDS;
        return S_OK;
    }
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD index, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** out) override {
        if (index >= FI_NUM_FIELDS || !out) return E_INVALIDARG;
        auto* d = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(**out));
        if (!d) return E_OUTOFMEMORY;
        *d = s_fields[index];
        HRESULT hr = SHStrDupW(s_fields[index].pszLabel, &d->pszLabel);
        if (FAILED(hr)) {
            CoTaskMemFree(d);
            return hr;
        }
        *out = d;
        return S_OK;
    }
    IFACEMETHODIMP GetCredentialCount(DWORD* count, DWORD* defaultIndex, BOOL* autoLogonWithDefault) override {
        *count = m_credential ? 1 : 0;
        bool ready = m_credential && m_credential->Ready();
        *defaultIndex = ready ? 0 : CREDENTIAL_PROVIDER_NO_DEFAULT;
        *autoLogonWithDefault = ready ? TRUE : FALSE;
        return S_OK;
    }
    IFACEMETHODIMP GetCredentialAt(DWORD index, ICredentialProviderCredential** out) override {
        if (index != 0 || !m_credential || !out) return E_INVALIDARG;
        return m_credential->QueryInterface(IID_ICredentialProviderCredential, (void**)out);
    }

    // ICredentialProviderSetUserArray (V2 provider: our credential attaches to a user tile)
    IFACEMETHODIMP SetUserArray(ICredentialProviderUserArray*) override { return S_OK; }

    // Called by the credential's poll thread when the device has been verified.
    void CredentialsReady() {
        EnterCriticalSection(&m_lock);
        ICredentialProviderEvents* ev = m_events;
        if (ev) ev->AddRef();
        UINT_PTR ctx = m_context;
        LeaveCriticalSection(&m_lock);
        if (ev) {
            ev->CredentialsChanged(ctx);
            ev->Release();
        }
    }

    Provider(const Provider&) = delete;

private:
    ~Provider() {
        if (m_credential) {
            m_credential->Shutdown();
            m_credential->Release();
        }
        if (m_events) m_events->Release();
        DeleteCriticalSection(&m_lock);
        DllRelease();
    }

    LONG m_refs = 1;
    CRITICAL_SECTION m_lock;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO m_cpus = CPUS_INVALID;
    Credential* m_credential = nullptr;
    ICredentialProviderEvents* m_events = nullptr;
    UINT_PTR m_context = 0;
};

// --- Credential implementation ----------------------------------------------------

Credential::Credential(Provider* provider, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, const std::wstring& sid)
    : m_provider(provider), m_cpus(cpus), m_sid(sid), m_status(L"Looking for your AuthKey...") {
    DllAddRef();
    InitializeCriticalSection(&m_lock);
}

Credential::~Credential() {
    SecureWipe(m_password);
    if (m_events) m_events->Release();
    DeleteCriticalSection(&m_lock);
    DllRelease();
}

void Credential::Shutdown() {
    m_stop = true;
    m_provider = nullptr;   // the provider is going away
}

IFACEMETHODIMP Credential::Advise(ICredentialProviderCredentialEvents* events) {
    EnterCriticalSection(&m_lock);
    if (m_events) m_events->Release();
    m_events = events;
    if (m_events) m_events->AddRef();
    LeaveCriticalSection(&m_lock);
    return S_OK;
}

IFACEMETHODIMP Credential::UnAdvise() {
    EnterCriticalSection(&m_lock);
    if (m_events) m_events->Release();
    m_events = nullptr;
    LeaveCriticalSection(&m_lock);
    return S_OK;
}

void Credential::SetStatus(PCWSTR text) {
    EnterCriticalSection(&m_lock);
    m_status = text;
    ICredentialProviderCredentialEvents* ev = m_events;
    if (ev) ev->AddRef();
    LeaveCriticalSection(&m_lock);
    if (ev) {
        ev->SetFieldString(this, FI_STATUS, text);
        ev->Release();
    }
}

bool Credential::TryUnlock() {
    std::string reply, tok[4];
    if (!PipeRequest("UNLOCK", reply, 3000)) {
        SetStatus(L"AuthKey service is not running");
        return false;
    }
    if (Tokens(reply, tok) == 4 && tok[0] == "OK") {
        EnterCriticalSection(&m_lock);
        m_domain = FromB64(tok[1].data(), tok[1].size());
        m_user = FromB64(tok[2].data(), tok[2].size());
        SecureWipe(m_password);
        m_password = FromB64(tok[3].data(), tok[3].size());
        LeaveCriticalSection(&m_lock);
        SecureZeroMemory(&reply[0], reply.size());
        SecureZeroMemory(&tok[3][0], tok[3].size());
        m_ready = !m_user.empty() && !m_password.empty();
        return m_ready;
    }
    SetStatus(L"AuthKey not found - plug it in or bring it closer");
    return false;
}

DWORD WINAPI Credential::PollThread(void* p) {
    Credential* self = static_cast<Credential*>(p);   // AddRef'd by the starter
    while (!self->m_stop && !self->m_ready && !self->m_failed) {
        if (self->TryUnlock()) {
            self->SetStatus(L"AuthKey verified - signing in...");
            Provider* provider = self->m_provider;
            if (provider && !self->m_stop) provider->CredentialsReady();
            break;
        }
        for (int i = 0; i < 15 && !self->m_stop; i++) Sleep(100);
    }
    self->m_polling = false;
    self->Release();
    return 0;
}

IFACEMETHODIMP Credential::SetSelected(BOOL* autoLogon) {
    *autoLogon = (m_ready && !m_failed) ? TRUE : FALSE;
    m_stop = false;
    if (!m_ready && !m_failed && !m_polling) {
        m_polling = true;
        AddRef();
        HANDLE t = CreateThread(nullptr, 0, PollThread, this, 0, nullptr);
        if (t) {
            CloseHandle(t);
        } else {
            m_polling = false;
            Release();
        }
    }
    return S_OK;
}

IFACEMETHODIMP Credential::SetDeselected() {
    m_stop = true;   // stop polling while another sign-in option is in use
    return S_OK;
}

IFACEMETHODIMP Credential::GetFieldState(DWORD id, CREDENTIAL_PROVIDER_FIELD_STATE* state,
                                         CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* istate) {
    if (id >= FI_NUM_FIELDS || !state || !istate) return E_INVALIDARG;
    *state = s_fieldStates[id];
    *istate = CPFIS_NONE;
    return S_OK;
}

IFACEMETHODIMP Credential::GetStringValue(DWORD id, PWSTR* value) {
    if (!value) return E_INVALIDARG;
    if (id == FI_LABEL) return SHStrDupW(L"AuthKey", value);
    if (id == FI_STATUS) {
        EnterCriticalSection(&m_lock);
        HRESULT hr = SHStrDupW(m_status.c_str(), value);
        LeaveCriticalSection(&m_lock);
        return hr;
    }
    return E_INVALIDARG;
}

IFACEMETHODIMP Credential::GetBitmapValue(DWORD id, HBITMAP* bmp) {
    if (id != FI_TILEIMAGE || !bmp) return E_INVALIDARG;
    *bmp = MakeTileBitmap();
    return *bmp ? S_OK : E_FAIL;
}

IFACEMETHODIMP Credential::GetSubmitButtonValue(DWORD id, DWORD* adjacent) {
    if (id != FI_SUBMIT || !adjacent) return E_INVALIDARG;
    *adjacent = FI_STATUS;
    return S_OK;
}

IFACEMETHODIMP Credential::GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* resp,
                                            CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* cs, PWSTR* statusText,
                                            CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) {
    *resp = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *statusText = nullptr;
    *statusIcon = CPSI_NONE;
    ZeroMemory(cs, sizeof(*cs));

    // Submit pressed before the device was found: try once now.
    if (!m_ready && !m_failed) TryUnlock();
    if (!m_ready) {
        SHStrDupW(m_failed ? L"Stored password was rejected. Re-run AuthKeyUnlock pair."
                           : L"AuthKey not found. Plug it in or bring it closer, then try again.",
                  statusText);
        *statusIcon = CPSI_ERROR;
        return S_OK;
    }

    EnterCriticalSection(&m_lock);
    std::wstring domain = m_domain, user = m_user, password = m_password;
    LeaveCriticalSection(&m_lock);

    // Logon / unlock want the password CredProtect-ed; CredUI wants it plain.
    if (m_cpus != CPUS_CREDUI) {
        CRED_PROTECTION_TYPE type;
        if (!CredIsProtectedW(&password[0], &type) || type == CredUnprotected) {
            DWORD cch = 0;
            CredProtectW(FALSE, &password[0], (DWORD)password.size() + 1, nullptr, &cch, nullptr);
            std::wstring prot(cch, L'\0');
            if (cch && CredProtectW(FALSE, &password[0], (DWORD)password.size() + 1, &prot[0], &cch, nullptr)) {
                prot.resize(cch ? cch - 1 : 0);
                SecureWipe(password);
                password = prot;
                SecureWipe(prot);
            }
        }
    }

    HRESULT hr = PackLogon(domain.c_str(), user.c_str(), password.c_str(), m_cpus, &cs->rgbSerialization,
                           &cs->cbSerialization);
    SecureWipe(password);
    if (FAILED(hr)) return hr;
    ULONG pkg = 0;
    hr = NegotiatePackage(&pkg);
    if (FAILED(hr)) {
        SecureZeroMemory(cs->rgbSerialization, cs->cbSerialization);
        CoTaskMemFree(cs->rgbSerialization);
        cs->rgbSerialization = nullptr;
        cs->cbSerialization = 0;
        return hr;
    }
    cs->ulAuthenticationPackage = pkg;
    cs->clsidCredentialProvider = CLSID_AuthKeyProvider;
    *resp = CPGSR_RETURN_CREDENTIAL_FINISHED;
    m_ready = false;   // single use; the next lock asks the device again
    return S_OK;
}

IFACEMETHODIMP Credential::ReportResult(NTSTATUS status, NTSTATUS, PWSTR* statusText,
                                        CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) {
    *statusText = nullptr;
    *statusIcon = CPSI_NONE;
    if (!NT_SUCCESS(status)) {
        // Never retry automatically: a wrong stored password must not lock the account out.
        m_failed = true;
        m_ready = false;
        EnterCriticalSection(&m_lock);
        SecureWipe(m_password);
        LeaveCriticalSection(&m_lock);
        SHStrDupW(L"Windows rejected the saved password (changed?). Sign in another way, then run AuthKeyUnlock pair.",
                  statusText);
        *statusIcon = CPSI_ERROR;
        SetStatus(L"Automatic sign-in paused");
    }
    return S_OK;
}

IFACEMETHODIMP Credential::GetUserSid(PWSTR* sid) {
    if (!sid) return E_INVALIDARG;
    return SHStrDupW(m_sid.c_str(), sid);
}

// --- Class factory & DLL exports ---------------------------------------------------

class ClassFactory : public IClassFactory {
public:
    IFACEMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&m_refs); }
    IFACEMETHODIMP_(ULONG) Release() override {
        LONG r = InterlockedDecrement(&m_refs);
        if (!r) delete this;
        return r;
    }
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_INVALIDARG;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP CreateInstance(IUnknown* outer, REFIID riid, void** ppv) override {
        if (outer) return CLASS_E_NOAGGREGATION;
        Provider* p = new (std::nothrow) Provider();
        if (!p) return E_OUTOFMEMORY;
        HRESULT hr = p->QueryInterface(riid, ppv);
        p->Release();
        return hr;
    }
    IFACEMETHODIMP LockServer(BOOL lock) override {
        if (lock) DllAddRef();
        else DllRelease();
        return S_OK;
    }

private:
    LONG m_refs = 1;
};

STDAPI DllCanUnloadNow() { return g_dllRefs > 0 ? S_FALSE : S_OK; }

STDAPI DllGetClassObject(REFCLSID clsid, REFIID riid, void** ppv) {
    if (clsid != CLSID_AuthKeyProvider) return CLASS_E_CLASSNOTAVAILABLE;
    ClassFactory* f = new (std::nothrow) ClassFactory();
    if (!f) return E_OUTOFMEMORY;
    HRESULT hr = f->QueryInterface(riid, ppv);
    f->Release();
    return hr;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, void*) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_hinst = hinst;
        DisableThreadLibraryCalls(hinst);
    }
    return TRUE;
}
