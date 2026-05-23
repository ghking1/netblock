#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <algorithm>
#include <rpc.h>
#include <sddl.h>
#include <ws2tcpip.h>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")

// FWPM_FILTER_ENUM_FLAG_INCLUDE_DYNAMIC was introduced in Windows 10 2004 (NTDDI_WIN10_MN).
// If the SDK doesn't define it yet, provide the value manually.
#ifndef FWPM_FILTER_ENUM_FLAG_INCLUDE_DYNAMIC
#define FWPM_FILTER_ENUM_FLAG_INCLUDE_DYNAMIC 0x00000020
#endif

// ============================================================================
// Well-known GUIDs for netblock sublayer and provider
// ============================================================================

// {0f524e41-c4f1-4de7-ad61-a0fc943b57b0}
static const GUID NETBLOCK_SUBLAYER_GUID =
    { 0x0f524e41, 0xc4f1, 0x4de7, { 0xad, 0x61, 0xa0, 0xfc, 0x94, 0x3b, 0x57, 0xb0 } };

// {237ecdaf-5a47-4c29-b7ec-571e2684b257}
static const GUID NETBLOCK_PROVIDER_GUID =
    { 0x237ecdaf, 0x5a47, 0x4c29, { 0xb7, 0xec, 0x57, 0x1e, 0x26, 0x84, 0xb2, 0x57 } };

static const wchar_t* NETBLOCK_NAME = L"netblock";

// ============================================================================
// Configuration struct for a filter rule
// ============================================================================

enum class Direction { In = 1, Out = 2, Both = 3 };
enum class Action { Block, Allow };

struct FilterConfig
{
    std::wstring name;
    std::wstring programPath;     // empty = all programs
    std::wstring remoteIP;        // empty = all IPs
    Direction    direction;
    std::wstring localPorts;      // empty = all ports
    std::wstring remotePorts;     // empty = all ports
    Action       action;
    bool         temporary;
};

// ============================================================================
// Forward declarations
// ============================================================================

static void PrintUsage();
static std::wstring GenerateUUID();
static std::string ToUtf8(const std::wstring& wstr);
static std::wstring FromUtf8(const std::string& str);
static std::wstring IPv4ToString(UINT32 addr);
static std::wstring IPv6ToString(const UINT8 addr[16]);
static int CountBits(UINT32 mask);
static bool TryParseUInt16(const std::wstring& s, UINT16& val);
static bool ParsePortString(const std::wstring& ports, std::vector<UINT16>& singlePorts, std::vector<FWP_RANGE0>& portRanges);
static bool ParseIPCIDR(const std::wstring& ipStr, bool& isV4, FWP_V4_ADDR_AND_MASK& v4am, FWP_V6_ADDR_AND_MASK& v6am, bool& isSingle);
static std::wstring GetFilterActionString(const FWPM_FILTER0& filter);
static std::wstring GetConditionValueString(HANDLE engine, const FWPM_FILTER_CONDITION0& cond);
static DWORD EnsureSublayer(HANDLE engine);
static DWORD AddFilter(HANDLE engine, const FilterConfig& cfg);
static DWORD DeleteFilterByName(HANDLE engine, const std::wstring& name);
static DWORD DeleteFilterByPath(HANDLE engine, const std::wstring& path);
static DWORD ListFilters(HANDLE engine);
static DWORD OpenEngine(HANDLE* phEngine, BOOL dynamicSession);

// ============================================================================
// PrintUsage
// ============================================================================

static void PrintUsage()
{
    wprintf(L"netblock <command> [options]\n\n");
    wprintf(L"Commands:\n");
    wprintf(L"  add    Add a blocking/filtering rule\n");
    wprintf(L"  del    Delete rule(s)\n");
    wprintf(L"  list   List all rules managed by netblock\n\n");
    wprintf(L"Options for 'add':\n");
    wprintf(L"  -n <name>         Rule name (for later management; default: auto-generated UUID)\n");
    wprintf(L"  -p <path>         Program absolute path (include .exe; default: all programs)\n");
    wprintf(L"  -a <ip/cidr>      Remote IP address (IPv4/IPv6, e.g. 192.168.1.1 or 2001:db8::/32)\n");
    wprintf(L"  -l <port|range>   Local port (e.g. 80; 8000-9000; 81,82,83; 81,82-85; default: all)\n");
    wprintf(L"  -r <port|range>   Remote port (same format as -l; default: all)\n");
    wprintf(L"  -e <block|allow>  Action (default: block)\n");
    wprintf(L"  -d <in|out|both>  Traffic direction (default: both)\n");
    wprintf(L"  -t                Set as temporary rule (default: persistent)\n\n");
    wprintf(L"Options for 'del':\n");
    wprintf(L"  -n <name>         Delete by rule name (recommended)\n");
    wprintf(L"  -p <path>         Delete all rules matching this program path (batch)\n\n");
    wprintf(L"Note: 'add' requires at least one filter condition (-p, -a, -l, or -r).\n");
}

// ============================================================================
// GenerateUUID
// ============================================================================

static std::wstring GenerateUUID()
{
    GUID guid;
    if (UuidCreate(&guid) != RPC_S_OK)
        UuidCreateSequential(&guid);

    wchar_t* wszGuid = nullptr;
    if (UuidToStringW(&guid, (RPC_WSTR*)&wszGuid) == RPC_S_OK && wszGuid)
    {
        std::wstring result(wszGuid);
        RpcStringFreeW((RPC_WSTR*)&wszGuid);
        return result;
    }
    return L"unknown";
}

// ============================================================================
// UTF-8 conversion
// ============================================================================

static std::string ToUtf8(const std::wstring& wstr)
{
    if (wstr.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(),
                                  nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string result(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(),
                        &result[0], len, nullptr, nullptr);
    return result;
}

static std::wstring FromUtf8(const std::string& str)
{
    if (str.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), nullptr, 0);
    if (len <= 0) return {};
    std::wstring result(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &result[0], len);
    return result;
}

// ============================================================================
// IPv4ToString / IPv6ToString
// ============================================================================

static std::wstring IPv4ToString(UINT32 addr)
{
    wchar_t buf[16];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%u.%u.%u.%u",
        (addr >> 24) & 0xFF, (addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF);
    return buf;
}

static std::wstring IPv6ToString(const UINT8 addr[16])
{
    SOCKADDR_IN6 sa6 = {};
    sa6.sin6_family = AF_INET6;
    memcpy(sa6.sin6_addr.u.Byte, addr, 16);

    wchar_t buf[46];
    DWORD bufLen = _countof(buf);
    if (WSAAddressToStringW((LPSOCKADDR)&sa6, sizeof(sa6), nullptr, buf, &bufLen) == 0)
        return buf;
    return L"<invalid-v6>";
}

// ============================================================================
// CountBits
// ============================================================================

static int CountBits(UINT32 mask)
{
    int bits = 0;
    while (mask) { bits++; mask &= (mask - 1); }
    return bits;
}

// ============================================================================
// TryParseUInt16
// ============================================================================

static bool TryParseUInt16(const std::wstring& s, UINT16& val)
{
    if (s.empty()) return false;
    wchar_t* end = nullptr;
    unsigned long v = wcstoul(s.c_str(), &end, 10);
    if (end == s.c_str() || *end != L'\0') return false;
    if (v > 65535) return false;
    val = (UINT16)v;
    return true;
}

// ============================================================================
// ParsePortString  -> "80", "8000-9000", "81,82,83", "81,82-85"
// ============================================================================

static bool ParsePortString(const std::wstring& ports,
                            std::vector<UINT16>& singlePorts,
                            std::vector<FWP_RANGE0>& portRanges)
{
    if (ports.empty()) return true;

    singlePorts.clear();
    portRanges.clear();

    std::wstring remaining = ports;
    while (!remaining.empty())
    {
        size_t commaPos = remaining.find(L',');
        std::wstring token;
        if (commaPos == std::wstring::npos)
        {
            token = remaining;
            remaining.clear();
        }
        else
        {
            token = remaining.substr(0, commaPos);
            remaining = remaining.substr(commaPos + 1);
        }

        while (!token.empty() && token.front() == L' ') token.erase(0, 1);
        while (!token.empty() && token.back() == L' ') token.pop_back();
        if (token.empty()) continue;

        size_t dashPos = token.find(L'-');
        if (dashPos != std::wstring::npos)
        {
            std::wstring lowStr  = token.substr(0, dashPos);
            std::wstring highStr = token.substr(dashPos + 1);
            while (!lowStr.empty()  && lowStr.front()  == L' ') lowStr.erase(0, 1);
            while (!lowStr.empty()  && lowStr.back()   == L' ') lowStr.pop_back();
            while (!highStr.empty() && highStr.front() == L' ') highStr.erase(0, 1);
            while (!highStr.empty() && highStr.back()  == L' ') highStr.pop_back();

            UINT16 low, high;
            if (!TryParseUInt16(lowStr, low) || !TryParseUInt16(highStr, high))
            {
                wprintf(L"ERROR: Invalid port range: %s\n", token.c_str());
                return false;
            }
            if (low > high)
            {
                wprintf(L"ERROR: Port range low > high: %s\n", token.c_str());
                return false;
            }
            FWP_RANGE0 range = {};
            range.valueLow.type  = FWP_UINT16;
            range.valueLow.uint16  = low;
            range.valueHigh.type = FWP_UINT16;
            range.valueHigh.uint16 = high;
            portRanges.push_back(range);
        }
        else
        {
            UINT16 port = 0;
            if (!TryParseUInt16(token, port))
            {
                wprintf(L"ERROR: Invalid port: %s\n", token.c_str());
                return false;
            }
            singlePorts.push_back(port);
        }
    }
    return true;
}

// ============================================================================
// ParseIPCIDR  -> "192.168.1.1", "192.168.1.0/24", "2001:db8::1", "2001:db8::/32"
// ============================================================================

static bool ParseIPCIDR(const std::wstring& ipStr,
                        bool& isV4,
                        FWP_V4_ADDR_AND_MASK& v4am,
                        FWP_V6_ADDR_AND_MASK& v6am,
                        bool& isSingle)
{
    if (ipStr.empty())
    {
        isV4 = false; isSingle = true;
        ZeroMemory(&v4am, sizeof(v4am));
        ZeroMemory(&v6am, sizeof(v6am));
        return true;
    }

    bool isIPv6 = (ipStr.find(L':') != std::wstring::npos);

    if (isIPv6)
    {
        isV4 = false;
        std::wstring addrPart = ipStr;
        UINT8 prefixLen = 128;

        size_t slashPos = ipStr.find(L'/');
        if (slashPos != std::wstring::npos)
        {
            addrPart  = ipStr.substr(0, slashPos);
            prefixLen = (UINT8)wcstoul(ipStr.substr(slashPos + 1).c_str(), nullptr, 10);
            if (prefixLen > 128)
            {
                wprintf(L"ERROR: Invalid IPv6 prefix length: %u\n", prefixLen);
                return false;
            }
        }

        SOCKADDR_IN6 sa6 = {};
        sa6.sin6_family = AF_INET6;
        INT addrLen = sizeof(sa6);
        if (WSAStringToAddressW((LPWSTR)addrPart.c_str(), AF_INET6, nullptr,
                                (LPSOCKADDR)&sa6, &addrLen) != 0)
        {
            wprintf(L"ERROR: Invalid IPv6 address: %s\n", addrPart.c_str());
            return false;
        }

        memcpy(&v6am.addr, sa6.sin6_addr.u.Byte, 16);
        v6am.prefixLength = prefixLen;
        isSingle = (slashPos == std::wstring::npos);
        return true;
    }
    else
    {
        isV4 = true;
        std::wstring addrPart = ipStr;
        UINT8 prefixLen = 32;

        size_t slashPos = ipStr.find(L'/');
        if (slashPos != std::wstring::npos)
        {
            addrPart  = ipStr.substr(0, slashPos);
            prefixLen = (UINT8)wcstoul(ipStr.substr(slashPos + 1).c_str(), nullptr, 10);
            if (prefixLen > 32)
            {
                wprintf(L"ERROR: Invalid IPv4 prefix length: %u\n", prefixLen);
                return false;
            }
        }

        std::string utf8Addr = ToUtf8(addrPart);
        IN_ADDR inAddr;
        if (inet_pton(AF_INET, utf8Addr.c_str(), &inAddr) != 1)
        {
            wprintf(L"ERROR: Invalid IPv4 address: %s\n", addrPart.c_str());
            return false;
        }

        v4am.addr = ntohl(inAddr.s_addr);
        v4am.mask = (prefixLen == 0) ? 0 : (0xFFFFFFFF << (32 - prefixLen));
        isSingle = (slashPos == std::wstring::npos);
        return true;
    }
}

// ============================================================================
// GetFilterActionString
// ============================================================================

static std::wstring GetFilterActionString(const FWPM_FILTER0& filter)
{
    switch (filter.action.type)
    {
    case FWP_ACTION_BLOCK:               return L"block";
    case FWP_ACTION_PERMIT:              return L"allow";
    case FWP_ACTION_CALLOUT_TERMINATING: return L"callout-term";
    case FWP_ACTION_CALLOUT_INSPECTION:  return L"callout-inspect";
    case FWP_ACTION_CALLOUT_UNKNOWN:     return L"callout-unknown";
    default:                             return L"unknown";
    }
}

// ============================================================================
// GetConditionValueString
// ============================================================================

static std::wstring GetConditionValueString(HANDLE engine, const FWPM_FILTER_CONDITION0& cond)
{
    UNREFERENCED_PARAMETER(engine);

    if (IsEqualGUID(cond.fieldKey, FWPM_CONDITION_IP_REMOTE_ADDRESS))
    {
        if (cond.conditionValue.type == FWP_V4_ADDR_MASK)
            return IPv4ToString(cond.conditionValue.v4AddrMask->addr) +
                   L"/" + std::to_wstring(CountBits(cond.conditionValue.v4AddrMask->mask));
        if (cond.conditionValue.type == FWP_V6_ADDR_MASK)
            return IPv6ToString((const UINT8*)&cond.conditionValue.v6AddrMask->addr) +
                   L"/" + std::to_wstring(cond.conditionValue.v6AddrMask->prefixLength);
    }
    else if (IsEqualGUID(cond.fieldKey, FWPM_CONDITION_IP_LOCAL_PORT) ||
             IsEqualGUID(cond.fieldKey, FWPM_CONDITION_IP_REMOTE_PORT))
    {
        if (cond.conditionValue.type == FWP_UINT16)
        {
            wchar_t buf[32];
            _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%hu", cond.conditionValue.uint16);
            return buf;
        }
        if (cond.conditionValue.type == FWP_RANGE_TYPE && cond.conditionValue.rangeValue)
        {
            wchar_t buf[64];
            _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%hu-%hu",
                cond.conditionValue.rangeValue->valueLow.uint16,
                cond.conditionValue.rangeValue->valueHigh.uint16);
            return buf;
        }
    }
    else if (IsEqualGUID(cond.fieldKey, FWPM_CONDITION_ALE_APP_ID))
    {
        return L"<app-filter>";
    }
    else
    {
        return L"<cond-guid>";
    }

    // Fallback for unrecognized type within known field
    wchar_t buf[32];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"<type:%d>", cond.conditionValue.type);
    return buf;
}

// ============================================================================
// OpenEngine
// ============================================================================

static DWORD OpenEngine(HANDLE* phEngine, BOOL dynamicSession)
{
    FWPM_SESSION0 session = {};
    session.displayData.name = (wchar_t*)NETBLOCK_NAME;
    session.displayData.description = (wchar_t*)L"netblock WFP management session";
    if (dynamicSession)
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    DWORD result = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, phEngine);
    if (result == ERROR_ACCESS_DENIED)
    {
        wprintf(L"ERROR: Access denied. This tool requires Administrator privileges.\n");
        wprintf(L"       Please run from an elevated command prompt.\n");
        return result;
    }
    if (result != ERROR_SUCCESS)
        return result;

    // Register provider (ignore if already registered)
    FWPM_PROVIDER0 provider = {};
    provider.providerKey = NETBLOCK_PROVIDER_GUID;
    provider.displayData.name = (wchar_t*)NETBLOCK_NAME;
    provider.displayData.description = (wchar_t*)L"netblock provider";
    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;

    // Ignore errors — provider may already exist
    FwpmProviderAdd0(*phEngine, &provider, nullptr);

    return ERROR_SUCCESS;
}

// ============================================================================
// EnsureSublayer
// ============================================================================

static DWORD EnsureSublayer(HANDLE engine)
{
    FWPM_SUBLAYER0* pSublayer = nullptr;
    DWORD result = FwpmSubLayerGetByKey0(engine, &NETBLOCK_SUBLAYER_GUID, &pSublayer);
    if (result == ERROR_SUCCESS)
    {
        FwpmFreeMemory((void**)&pSublayer);
        return ERROR_SUCCESS;
    }

    if (result == ERROR_ACCESS_DENIED)
    {
        wprintf(L"ERROR: Access denied. This tool requires Administrator privileges.\n");
        wprintf(L"       Please run from an elevated command prompt.\n");
        return result;
    }
    if (result != FWP_E_SUBLAYER_NOT_FOUND)
        return result;

    FWPM_SUBLAYER0 sl = {};
    sl.subLayerKey = NETBLOCK_SUBLAYER_GUID;
    sl.displayData.name = (wchar_t*)NETBLOCK_NAME;
    sl.displayData.description = (wchar_t*)L"netblock managed rules";
    sl.providerKey = (GUID*)&NETBLOCK_PROVIDER_GUID;
    sl.weight = 0x8000;
    sl.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;

    result = FwpmSubLayerAdd0(engine, &sl, nullptr);
    if (result == FWP_E_ALREADY_EXISTS)
        result = ERROR_SUCCESS;
    return result;
}

// ============================================================================
// TryAddSingleFilter - attempt to add one filter; returns ERROR_SUCCESS or error
// ============================================================================

static DWORD TryAddSingleFilter(HANDLE engine,
                                const GUID& layerKey,
                                const GUID& subLayerKey,
                                const GUID* pProviderKey,
                                const FWPM_FILTER_CONDITION0* conditions,
                                UINT32 numConditions,
                                const FilterConfig& cfg,
                                UINT64* pFilterId)
{
    FWPM_FILTER0 f = {};
    f.layerKey        = layerKey;
    f.subLayerKey     = subLayerKey;
    f.displayData.name = (wchar_t*)cfg.name.c_str();
    f.displayData.description = (wchar_t*)(cfg.temporary ? L"[TEMPORARY] netblock rule" : L"netblock rule");
    f.action.type = (cfg.action == Action::Block) ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
    f.weight.type = FWP_EMPTY;
    f.flags       = cfg.temporary ? 0 : FWPM_FILTER_FLAG_PERSISTENT;
    f.numFilterConditions = numConditions;
    f.filterCondition = (FWPM_FILTER_CONDITION0*)conditions;
    if (pProviderKey)
        f.providerKey = (GUID*)pProviderKey;

    return FwpmFilterAdd0(engine, &f, nullptr, pFilterId);
}

// ============================================================================
// AddFilter
// ============================================================================

static DWORD AddFilter(HANDLE engine, const FilterConfig& cfg)
{
    if (cfg.programPath.empty() && cfg.remoteIP.empty() &&
        cfg.localPorts.empty() && cfg.remotePorts.empty())
    {
        wprintf(L"ERROR: At least one filter condition (-p, -a, -l, or -r) is required.\n");
        return ERROR_INVALID_PARAMETER;
    }

    // --- Parse IP ---
    bool ipV4 = false;
    FWP_V4_ADDR_AND_MASK v4am = {};
    FWP_V6_ADDR_AND_MASK v6am = {};
    bool ipSingle = true;
    if (!ParseIPCIDR(cfg.remoteIP, ipV4, v4am, v6am, ipSingle))
        return ERROR_INVALID_PARAMETER;
    bool hasIP = !cfg.remoteIP.empty();

    // --- Parse ports ---
    std::vector<UINT16>     localSinglePorts, remoteSinglePorts;
    std::vector<FWP_RANGE0> localPortRanges,  remotePortRanges;

    if (!ParsePortString(cfg.localPorts,  localSinglePorts,  localPortRanges)  ||
        !ParsePortString(cfg.remotePorts, remoteSinglePorts, remotePortRanges))
        return ERROR_INVALID_PARAMETER;

    bool hasLocalPorts  = !localSinglePorts.empty()  || !localPortRanges.empty();
    bool hasRemotePorts = !remoteSinglePorts.empty() || !remotePortRanges.empty();

    // --- Get App ID ---
    FWP_BYTE_BLOB* pAppId = nullptr;
    if (!cfg.programPath.empty())
    {
        DWORD res = FwpmGetAppIdFromFileName0(cfg.programPath.c_str(), &pAppId);
        if (res != ERROR_SUCCESS)
        {
            wprintf(L"ERROR: Failed to get app ID for '%s' (code: %lu)\n",
                    cfg.programPath.c_str(), res);
            return res;
        }
    }

    // --- Build layer list ---
    struct LayerEntry { GUID key; bool isV4; };
    std::vector<LayerEntry> layers;

    if (cfg.direction == Direction::Out || cfg.direction == Direction::Both)
    {
        if (!hasIP || ipV4)  layers.push_back({ FWPM_LAYER_ALE_AUTH_CONNECT_V4,      true });
        if (!hasIP || !ipV4) layers.push_back({ FWPM_LAYER_ALE_AUTH_CONNECT_V6,      false });
    }
    if (cfg.direction == Direction::In || cfg.direction == Direction::Both)
    {
        if (!hasIP || ipV4)  layers.push_back({ FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,  true });
        if (!hasIP || !ipV4) layers.push_back({ FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,  false });
    }

    DWORD lastError = ERROR_SUCCESS;
    int   filterCount = 0;

    for (const auto& layer : layers)
    {
        std::vector<FWPM_FILTER_CONDITION0> conditions;

        // App ID
        if (pAppId)
        {
            FWPM_FILTER_CONDITION0 c = {};
            c.fieldKey = FWPM_CONDITION_ALE_APP_ID;
            c.matchType = FWP_MATCH_EQUAL;
            c.conditionValue.type = FWP_BYTE_BLOB_TYPE;
            c.conditionValue.byteBlob = pAppId;
            conditions.push_back(c);
        }

        // Remote IP
        if (hasIP)
        {
            if ((layer.isV4 && !ipV4) || (!layer.isV4 && ipV4))
                continue; // IP version mismatch → skip this layer

            FWPM_FILTER_CONDITION0 c = {};
            c.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
            c.matchType = FWP_MATCH_EQUAL;
            if (ipV4)
            {
                c.conditionValue.type = FWP_V4_ADDR_MASK;
                c.conditionValue.v4AddrMask = &v4am;
            }
            else
            {
                c.conditionValue.type = FWP_V6_ADDR_MASK;
                c.conditionValue.v6AddrMask = &v6am;
            }
            conditions.push_back(c);
        }

        // Local ports
        for (UINT16 port : localSinglePorts)
        {
            FWPM_FILTER_CONDITION0 c = {};
            c.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
            c.matchType = FWP_MATCH_EQUAL;
            c.conditionValue.type = FWP_UINT16;
            c.conditionValue.uint16 = port;
            conditions.push_back(c);
        }
        for (auto& r : localPortRanges)
        {
            FWPM_FILTER_CONDITION0 c = {};
            c.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
            c.matchType = FWP_MATCH_RANGE;
            c.conditionValue.type = FWP_RANGE_TYPE;
            c.conditionValue.rangeValue = &r;
            conditions.push_back(c);
        }

        // Remote ports
        for (UINT16 port : remoteSinglePorts)
        {
            FWPM_FILTER_CONDITION0 c = {};
            c.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
            c.matchType = FWP_MATCH_EQUAL;
            c.conditionValue.type = FWP_UINT16;
            c.conditionValue.uint16 = port;
            conditions.push_back(c);
        }
        for (auto& r : remotePortRanges)
        {
            FWPM_FILTER_CONDITION0 c = {};
            c.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
            c.matchType = FWP_MATCH_RANGE;
            c.conditionValue.type = FWP_RANGE_TYPE;
            c.conditionValue.rangeValue = &r;
            conditions.push_back(c);
        }

        // --- Try primary approach ---
        UINT64 filterId = 0;
        DWORD res = TryAddSingleFilter(engine, layer.key, NETBLOCK_SUBLAYER_GUID,
                                       &NETBLOCK_PROVIDER_GUID,
                                       conditions.data(), (UINT32)conditions.size(),
                                       cfg, &filterId);

        if (res == ERROR_SUCCESS)
        {
            filterCount++;
            continue;
        }

        // --- If we got CALLOUT_NOTIFICATION_FAILURE, try fallback strategies ---
        if (res == 0x80320016) // FWP_E_CALLOUT_NOTIFICATION_FAILURE
        {
            bool recovered = false;
            GUID nullGuid = {};

            // Fallback 1: Try without provider key
            DWORD res2 = TryAddSingleFilter(engine, layer.key, NETBLOCK_SUBLAYER_GUID,
                                            nullptr,
                                            conditions.data(), (UINT32)conditions.size(),
                                            cfg, &filterId);
            if (res2 == ERROR_SUCCESS)
            {
                filterCount++;
                recovered = true;
            }

            // Fallback 2: Try with provider key but on default sublayer
            if (!recovered)
            {
                DWORD res3 = TryAddSingleFilter(engine, layer.key, nullGuid,
                                                &NETBLOCK_PROVIDER_GUID,
                                                conditions.data(), (UINT32)conditions.size(),
                                                cfg, &filterId);
                if (res3 == ERROR_SUCCESS)
                {
                    filterCount++;
                    recovered = true;
                }
            }

            // Fallback 3: Last resort - no sublayer, no provider
            // Prefix name with "netblock-" so it can be identified in list/del
            if (!recovered)
            {
                FilterConfig cfgWithPrefix = cfg;
                cfgWithPrefix.name = L"netblock-" + cfg.name;
                DWORD res4 = TryAddSingleFilter(engine, layer.key, nullGuid,
                                                nullptr,
                                                conditions.data(), (UINT32)conditions.size(),
                                                cfgWithPrefix, &filterId);
                if (res4 == ERROR_SUCCESS)
                {
                    filterCount++;
                    recovered = true;
                }
            }

            if (!recovered)
            {
                lastError = res;
                wprintf(L"WARNING: Failed to add filter on layer %s: error %lu (0x%08X)\n", layer.isV4 ? L"IPv4" : L"IPv6", res, res);
            }
        }
        else
        {
            lastError = res;
            wprintf(L"WARNING: Failed to add filter on layer %s: error %lu (0x%08X)\n", layer.isV4 ? L"IPv4" : L"IPv6", res, res);
        }
    }

    if (pAppId)
        FwpmFreeMemory((void**)&pAppId);

    if (filterCount == 0)
    {
        wprintf(L"ERROR: No filters were added (last error: %lu)\n", lastError);
        return (lastError != ERROR_SUCCESS) ? lastError : ERROR_GEN_FAILURE;
    }

    wprintf(L"SUCCESS: Added %d filter(s) for rule '%s'\n", filterCount, cfg.name.c_str());
    return ERROR_SUCCESS;
}

// ============================================================================
// IsNetblockFilter - check if a filter belongs to netblock (by sublayer or provider)
// ============================================================================

static bool IsNetblockFilter(const FWPM_FILTER0* f)
{
    if (IsEqualGUID(f->subLayerKey, NETBLOCK_SUBLAYER_GUID))
        return true;
    if (f->providerKey && IsEqualGUID(*f->providerKey, NETBLOCK_PROVIDER_GUID))
        return true;
    if (f->displayData.name && wcsncmp(f->displayData.name, L"netblock-", 9) == 0)
        return true;
    return false;
}

// ============================================================================
// CreateFilterEnumHandle - tries dynamic flag first; falls back on older OS
// ============================================================================

static DWORD CreateFilterEnumHandle(HANDLE engine, HANDLE* phEnum)
{
    FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate = {};
    enumTemplate.flags = FWPM_FILTER_ENUM_FLAG_INCLUDE_DYNAMIC;
    DWORD result = FwpmFilterCreateEnumHandle0(engine, &enumTemplate, phEnum);
    if (result == ERROR_SUCCESS)
        return ERROR_SUCCESS;
    // Fallback for older Windows (pre-2004) that don't support the dynamic flag
    return FwpmFilterCreateEnumHandle0(engine, nullptr, phEnum);
}

// ============================================================================
// DeleteFilterByName
// ============================================================================

static DWORD DeleteFilterByName(HANDLE engine, const std::wstring& name)
{
    HANDLE enumHandle = nullptr;
    DWORD result = CreateFilterEnumHandle(engine, &enumHandle);
    if (result != ERROR_SUCCESS)
    {
        wprintf(L"ERROR: Failed to create filter enumeration handle: %lu\n", result);
        return result;
    }

    UINT32 numEntries = 0;
    FWPM_FILTER0** filters = nullptr;
    result = FwpmFilterEnum0(engine, enumHandle, 4096, &filters, &numEntries);
    FwpmFilterDestroyEnumHandle0(engine, enumHandle);
    if (result != ERROR_SUCCESS)
    {
        wprintf(L"ERROR: Failed to enumerate filters: %lu\n", result);
        return result;
    }

    std::wstring prefixedName = L"netblock-" + name;
    int deleted = 0;
    for (UINT32 i = 0; i < numEntries; i++)
    {
        FWPM_FILTER0* f = filters[i];
        if (!IsNetblockFilter(f))
            continue;

        bool nameMatch = false;
        if (f->displayData.name)
        {
            if (name == f->displayData.name)
                nameMatch = true;
            else if (prefixedName == f->displayData.name)
                nameMatch = true;
        }

        if (nameMatch)
        {
            result = FwpmFilterDeleteByKey0(engine, &f->filterKey);
            if (result == ERROR_SUCCESS)
            {
                wprintf(L"Deleted rule: '%s'\n", f->displayData.name ? f->displayData.name : name.c_str());
                deleted++;
            }
            else
                wprintf(L"WARNING: Failed to delete rule '%s': %lu\n", f->displayData.name ? f->displayData.name : name.c_str(), result);
        }
    }

    FwpmFreeMemory((void**)&filters);
    if (deleted == 0)
        wprintf(L"No rules found with name '%s'\n", name.c_str());

    return ERROR_SUCCESS;
}

// ============================================================================
// DeleteFilterByPath
// ============================================================================

static DWORD DeleteFilterByPath(HANDLE engine, const std::wstring& path)
{
    FWP_BYTE_BLOB* pTargetAppId = nullptr;
    DWORD result = FwpmGetAppIdFromFileName0(path.c_str(), &pTargetAppId);
    if (result != ERROR_SUCCESS)
    {
        wprintf(L"ERROR: Failed to get app ID for '%s': %lu\n", path.c_str(), result);
        return result;
    }

    HANDLE enumHandle = nullptr;
    result = CreateFilterEnumHandle(engine, &enumHandle);
    if (result != ERROR_SUCCESS)
    {
        wprintf(L"ERROR: Failed to create filter enumeration handle: %lu\n", result);
        FwpmFreeMemory((void**)&pTargetAppId);
        return result;
    }

    UINT32 numEntries = 0;
    FWPM_FILTER0** filters = nullptr;
    result = FwpmFilterEnum0(engine, enumHandle, 4096, &filters, &numEntries);
    FwpmFilterDestroyEnumHandle0(engine, enumHandle);
    if (result != ERROR_SUCCESS)
    {
        wprintf(L"ERROR: Failed to enumerate filters: %lu\n", result);
        FwpmFreeMemory((void**)&pTargetAppId);
        return result;
    }

    int deleted = 0;
    for (UINT32 i = 0; i < numEntries; i++)
    {
        FWPM_FILTER0* f = filters[i];
        if (!IsNetblockFilter(f))
            continue;

        bool hasAppCond = false, appMatch = false;
        for (UINT32 j = 0; j < f->numFilterConditions; j++)
        {
            const FWPM_FILTER_CONDITION0& c = f->filterCondition[j];
            if (IsEqualGUID(c.fieldKey, FWPM_CONDITION_ALE_APP_ID) &&
                c.conditionValue.type == FWP_BYTE_BLOB_TYPE &&
                c.conditionValue.byteBlob)
            {
                hasAppCond = true;
                if (pTargetAppId->size == c.conditionValue.byteBlob->size &&
                    memcmp(pTargetAppId->data, c.conditionValue.byteBlob->data,
                           pTargetAppId->size) == 0)
                    appMatch = true;
                break;
            }
        }
        if (hasAppCond && appMatch)
        {
            result = FwpmFilterDeleteByKey0(engine, &f->filterKey);
            if (result == ERROR_SUCCESS)
            {
                wprintf(L"Deleted rule: '%s'\n",
                    f->displayData.name ? f->displayData.name : L"(unnamed)");
                deleted++;
            }
            else
                wprintf(L"WARNING: Failed to delete rule: %lu\n", result);
        }
    }

    FwpmFreeMemory((void**)&filters);
    FwpmFreeMemory((void**)&pTargetAppId);

    if (deleted == 0)
        wprintf(L"No rules found matching program path '%s'\n", path.c_str());

    return ERROR_SUCCESS;
}

// ============================================================================
// ListFilters
// ============================================================================

static DWORD ListFilters(HANDLE engine)
{
    HANDLE enumHandle = nullptr;
    DWORD result = CreateFilterEnumHandle(engine, &enumHandle);
    if (result != ERROR_SUCCESS)
    {
        wprintf(L"ERROR: Failed to create filter enumeration handle: %lu\n", result);
        return result;
    }

    UINT32 numEntries = 0;
    FWPM_FILTER0** filters = nullptr;
    result = FwpmFilterEnum0(engine, enumHandle, 4096, &filters, &numEntries);
    FwpmFilterDestroyEnumHandle0(engine, enumHandle);
    if (result != ERROR_SUCCESS)
    {
        wprintf(L"ERROR: Failed to enumerate filters: %lu\n", result);
        return result;
    }

    int netblockCount = 0;
    for (UINT32 i = 0; i < numEntries; i++)
        if (IsNetblockFilter(filters[i]))
            netblockCount++;

    if (netblockCount == 0)
    {
        wprintf(L"No netblock rules found.\n");
        FwpmFreeMemory((void**)&filters);
        return ERROR_SUCCESS;
    }

    wprintf(L"Total netblock rules: %d\n\n", netblockCount);

    int index = 0;
    for (UINT32 i = 0; i < numEntries; i++)
    {
        FWPM_FILTER0* f = filters[i];
        if (!IsNetblockFilter(f))
            continue;

        index++;
        wprintf(L"--- Rule #%d ---\n", index);
        wprintf(L"  Name:        %s\n",
                f->displayData.name ? f->displayData.name : L"(unnamed)");

        std::wstring appPath    = L"<all>";
        std::wstring remoteIP   = L"<all>";
        std::wstring localPort  = L"<all>";
        std::wstring remotePort = L"<all>";

        for (UINT32 j = 0; j < f->numFilterConditions; j++)
        {
            const FWPM_FILTER_CONDITION0& c = f->filterCondition[j];
            if (IsEqualGUID(c.fieldKey, FWPM_CONDITION_ALE_APP_ID))
                appPath = GetConditionValueString(engine, c);
            else if (IsEqualGUID(c.fieldKey, FWPM_CONDITION_IP_REMOTE_ADDRESS))
                remoteIP = GetConditionValueString(engine, c);
            else if (IsEqualGUID(c.fieldKey, FWPM_CONDITION_IP_LOCAL_PORT))
                localPort = GetConditionValueString(engine, c);
            else if (IsEqualGUID(c.fieldKey, FWPM_CONDITION_IP_REMOTE_PORT))
                remotePort = GetConditionValueString(engine, c);
        }

        wprintf(L"  Program:     %s\n", appPath.c_str());
        wprintf(L"  Remote IP:   %s\n", remoteIP.c_str());
        wprintf(L"  Local Port:  %s\n", localPort.c_str());
        wprintf(L"  Remote Port: %s\n", remotePort.c_str());

        bool inbound  = IsEqualGUID(f->layerKey, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4) ||
                        IsEqualGUID(f->layerKey, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6);
        bool outbound = IsEqualGUID(f->layerKey, FWPM_LAYER_ALE_AUTH_CONNECT_V4) ||
                        IsEqualGUID(f->layerKey, FWPM_LAYER_ALE_AUTH_CONNECT_V6);

        const wchar_t* dirStr = L"?";
        if (inbound && !outbound)      dirStr = L"in";
        else if (!inbound && outbound) dirStr = L"out";

        wprintf(L"  Action:      %s\n", GetFilterActionString(*f).c_str());
        wprintf(L"  Direction:   %s\n", dirStr);
        wprintf(L"  Type:        %s\n",
                (f->flags & FWPM_FILTER_FLAG_PERSISTENT) ? L"persistent" : L"temporary");

        if (f->displayData.description && wcslen(f->displayData.description) > 0)
            wprintf(L"  Desc:        %s\n", f->displayData.description);

        wprintf(L"\n");
    }

    FwpmFreeMemory((void**)&filters);
    return ERROR_SUCCESS;
}

// ============================================================================
// wmain
// ============================================================================

int wmain(int argc, wchar_t* argv[])
{
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    if (argc < 2)
    {
        PrintUsage();
        WSACleanup();
        return 1;
    }

    std::wstring command = argv[1];

    if (command == L"-h" || command == L"--help" || command == L"help")
    {
        PrintUsage();
        WSACleanup();
        return 0;
    }

    if (command != L"add" && command != L"del" && command != L"list")
    {
        PrintUsage();
        WSACleanup();
        return 1;
    }

    // ---- LIST ----
    if (command == L"list")
    {
        HANDLE engine = nullptr;
        DWORD res = OpenEngine(&engine, FALSE);
        if (res != ERROR_SUCCESS)
        {
            wprintf(L"ERROR: Failed to open WFP engine: %lu\n", res);
            WSACleanup();
            return 1;
        }
        res = EnsureSublayer(engine);
        if (res != ERROR_SUCCESS)
        {
            wprintf(L"ERROR: Failed to ensure sublayer: %lu\n", res);
            FwpmEngineClose0(engine);
            WSACleanup();
            return 1;
        }
        res = ListFilters(engine);
        FwpmEngineClose0(engine);
        WSACleanup();
        return (res == ERROR_SUCCESS) ? 0 : 1;
    }

    // ---- Parse options ----
    FilterConfig cfg;
    cfg.action    = Action::Block;
    cfg.direction = Direction::Both;
    cfg.temporary = false;

    std::wstring delName, delPath;
    bool hasDelName = false, hasDelPath = false;

    for (int i = 2; i < argc; i++)
    {
        std::wstring arg = argv[i];

        if (command == L"add")
        {
            if (arg == L"-n" && i + 1 < argc)      { cfg.name        = argv[++i]; }
            else if (arg == L"-p" && i + 1 < argc) {
                cfg.programPath = argv[++i];
                std::replace(cfg.programPath.begin(), cfg.programPath.end(), L'/', L'\\');
            }
            else if (arg == L"-a" && i + 1 < argc)  { cfg.remoteIP    = argv[++i]; }
            else if (arg == L"-d" && i + 1 < argc) {
                std::wstring d = argv[++i];
                if      (d == L"in")   cfg.direction = Direction::In;
                else if (d == L"out")  cfg.direction = Direction::Out;
                else if (d == L"both") cfg.direction = Direction::Both;
                else {
                    wprintf(L"ERROR: Invalid direction '%s'. Use in, out, or both.\n", d.c_str());
                    WSACleanup(); return 1;
                }
            }
            else if (arg == L"-l" && i + 1 < argc)  { cfg.localPorts  = argv[++i]; }
            else if (arg == L"-r" && i + 1 < argc)  { cfg.remotePorts = argv[++i]; }
            else if (arg == L"-e" && i + 1 < argc) {
                std::wstring a = argv[++i];
                if      (a == L"block") cfg.action = Action::Block;
                else if (a == L"allow") cfg.action = Action::Allow;
                else {
                    wprintf(L"ERROR: Invalid action '%s'. Use block or allow.\n", a.c_str());
                    WSACleanup(); return 1;
                }
            }
            else if (arg == L"-t")                   { cfg.temporary   = true; }
            else {
                PrintUsage();
                WSACleanup(); return 1;
            }
        }
        else if (command == L"del")
        {
            if (arg == L"-n" && i + 1 < argc) {
                delName = argv[++i]; hasDelName = true;
            }
            else if (arg == L"-p" && i + 1 < argc) {
                delPath = argv[++i];
                std::replace(delPath.begin(), delPath.end(), L'/', L'\\');
                hasDelPath = true;
            }
            else {
                PrintUsage();
                WSACleanup(); return 1;
            }
        }
    }

    // ---- ADD ----
    if (command == L"add")
    {
        if (cfg.name.empty())
            cfg.name = GenerateUUID();

        HANDLE engine = nullptr;
        DWORD res = OpenEngine(&engine, FALSE);
        if (res != ERROR_SUCCESS)
        {
            wprintf(L"ERROR: Failed to open WFP engine: %lu\n", res);
            WSACleanup(); return 1;
        }
        res = EnsureSublayer(engine);
        if (res != ERROR_SUCCESS)
        {
            wprintf(L"ERROR: Failed to ensure sublayer: %lu\n", res);
            FwpmEngineClose0(engine);
            WSACleanup(); return 1;
        }
        res = AddFilter(engine, cfg);
        FwpmEngineClose0(engine);
        WSACleanup();
        return (res == ERROR_SUCCESS) ? 0 : 1;
    }

    // ---- DEL ----
    if (command == L"del")
    {
        if (!hasDelName && !hasDelPath)
        {
            wprintf(L"ERROR: Must specify either -n <name> or -p <path>\n\n");
            PrintUsage();
            WSACleanup(); return 1;
        }

        HANDLE engine = nullptr;
        DWORD res = OpenEngine(&engine, FALSE);
        if (res != ERROR_SUCCESS)
        {
            wprintf(L"ERROR: Failed to open WFP engine: %lu\n", res);
            WSACleanup(); return 1;
        }
        res = EnsureSublayer(engine);
        if (res != ERROR_SUCCESS)
        {
            wprintf(L"ERROR: Failed to ensure sublayer: %lu\n", res);
            FwpmEngineClose0(engine);
            WSACleanup(); return 1;
        }

        DWORD delRes = ERROR_SUCCESS;
        if (hasDelName) delRes = DeleteFilterByName(engine, delName);
        if (hasDelPath) delRes = DeleteFilterByPath(engine, delPath);

        FwpmEngineClose0(engine);
        WSACleanup();
        return (delRes == ERROR_SUCCESS) ? 0 : 1;
    }

    WSACleanup();
    return 0;
}
