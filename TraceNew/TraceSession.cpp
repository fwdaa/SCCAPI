#include "TraceSession.hpp"
#include "TraceProvider.h"
#include "TraceETW.hpp"

///////////////////////////////////////////////////////////////////////////////
// ��������� ������������ ������ 
///////////////////////////////////////////////////////////////////////////////
static ULONG CheckSessionMode(ULONG mode)
{
    // ��� ����������� ������������� ������������ �������
    if (mode & EVENT_TRACE_DELAY_OPEN_FILE_MODE) return 0; 
    if (mode & EVENT_TRACE_ADD_HEADER_MODE     ) return 0; 
    if (mode & EVENT_TRACE_RELOG_MODE          ) return 0; 

    // ������ � ���������� ������ ���������� � ������
    if (mode & EVENT_TRACE_USE_KBYTES_FOR_SIZE) return 0; 

    // ��������� ����������������� ������
    if ((mode & EVENT_TRACE_USE_GLOBAL_SEQUENCE) &&
        (mode & EVENT_TRACE_USE_LOCAL_SEQUENCE )) return 0; 

    // ��� ��������������� ������
    if (mode & EVENT_TRACE_BUFFERING_MODE)
    {
        // ��������� ������������ ����������
        if (mode & EVENT_TRACE_FILE_MODE_CIRCULAR   ) return 0; 
        if (mode & EVENT_TRACE_FILE_MODE_SEQUENTIAL ) return 0; 
        if (mode & EVENT_TRACE_FILE_MODE_NEWFILE    ) return 0; 
        if (mode & EVENT_TRACE_FILE_MODE_APPEND     ) return 0; 
        if (mode & EVENT_TRACE_FILE_MODE_PREALLOCATE) return 0; 
        if (mode & EVENT_TRACE_REAL_TIME_MODE       ) return 0;

        // ������� ������������ �����
        return EVENT_TRACE_BUFFERING_MODE; 
    }
    // � ������ ��������� �������
    if (mode & EVENT_TRACE_REAL_TIME_MODE)
    {
        // ��������� ������������ ����������
        if (mode & EVENT_TRACE_FILE_MODE_APPEND) return 0; 
    }
    // ��� ������������ ���������� �����
    if (mode & EVENT_TRACE_FILE_MODE_CIRCULAR)
    {
        // ��������� ������������ ����������
        if (mode & EVENT_TRACE_FILE_MODE_SEQUENTIAL) return 0; 
        if (mode & EVENT_TRACE_FILE_MODE_NEWFILE   ) return 0; 
        if (mode & EVENT_TRACE_FILE_MODE_APPEND    ) return 0; 

        // ������� ������������ �����
        return EVENT_TRACE_FILE_MODE_CIRCULAR | (mode & EVENT_TRACE_REAL_TIME_MODE); 
    }
    // ��� ����������������� ���������� ���������� ������
    else if (mode & EVENT_TRACE_FILE_MODE_NEWFILE)
    {
        // ��������� ������������ ����������
        if (mode & EVENT_TRACE_FILE_MODE_CIRCULAR  ) return 0; 
        if (mode & EVENT_TRACE_FILE_MODE_SEQUENTIAL) return 0; 
        if (mode & EVENT_TRACE_FILE_MODE_APPEND    ) return 0; 

        // ������� ������������ �����
        return EVENT_TRACE_FILE_MODE_NEWFILE | (mode & EVENT_TRACE_REAL_TIME_MODE); 
    }
    else {
        // ��������� ������������ ����������
        if (mode & EVENT_TRACE_FILE_MODE_CIRCULAR  ) return 0; 
        if (mode & EVENT_TRACE_FILE_MODE_NEWFILE   ) return 0; 

        // ������� ������������ �����
        return EVENT_TRACE_FILE_MODE_SEQUENTIAL | (mode & EVENT_TRACE_REAL_TIME_MODE); 
    }
}

///////////////////////////////////////////////////////////////////////////////
// ������������� ��� �������
///////////////////////////////////////////////////////////////////////////////
inline ULONG ConvertTimestampType(ETW::TimestampType timerType)
{
    switch (timerType)
    {
    case ETW::TimestampType::QPC     : return 1; 
    case ETW::TimestampType::FileTime: return 2; 
    case ETW::TimestampType::TSC     : return 3; 
    }
    return 0; 
}
inline ETW::TimestampType ConvertTimestampType(ULONG timerType)
{
    switch (timerType)
    {
    case 1: return ETW::TimestampType::QPC     ; 
    case 2: return ETW::TimestampType::FileTime; 
    case 3: return ETW::TimestampType::TSC     ; 
    }
    return (ETW::TimestampType)0; 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ������ ������
///////////////////////////////////////////////////////////////////////////////
static GUID CreateSessionSecurity(PSECURITY_DESCRIPTOR pSecurityDescriptor) 
{
    // ��������� ������� ����������� ������
    GUID guid = GUID_NULL; if (!pSecurityDescriptor) return guid; 

    // ������� ���������� �������������
    RPC_STATUS status = ::UuidCreate(&guid); if (status != RPC_S_OK) 
    {
        // ��������� ���������� ������
        ETW::Exception::Throw(HRESULT_FROM_WIN32(status)); 
    }
    // ���������������� ����������
    PACL pDacl = nullptr; BOOL daclPresent = FALSE; BOOL daclDefaulted = FALSE; 
    PACL pSacl = nullptr; BOOL saclPresent = FALSE; BOOL saclDefaulted = FALSE; 

    // �������� ������ DACL
    if (!::GetSecurityDescriptorDacl(
        pSecurityDescriptor, &daclPresent, &pDacl, &daclDefaulted))
    {
        // ��� ������ ��������� ����������
        ETW::Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
    }
    // �������� ������ DACL
    if (!::GetSecurityDescriptorSacl(
        pSecurityDescriptor, &saclPresent, &pSacl, &saclDefaulted))
    {
        // ��� ������ ��������� ����������
        ETW::Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
    }
    try { 
        // ��� ���� ��������� ������ DACL
        if (pDacl) for (DWORD i = 0; i < pDacl->AceCount; i++)
        {
            // �������� ������� �������� �������
            PACE_HEADER pAceHeader = nullptr; if (!::GetAce(pDacl, i, (void**)&pAceHeader))
            {
                // ��� ������ ��������� ����������
                ETW::Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
            }
            switch (pAceHeader->AceType)
            {
            // ��� ������������ �������� �������� �������
            case ACCESS_ALLOWED_ACE_TYPE: 
            {
                // ��������� �������������� ����
                PACCESS_ALLOWED_ACE pAce = (PACCESS_ALLOWED_ACE)pAceHeader; 

                // ���������� ����������� ������
                if (!::EventAccessControl(&guid, EventSecurityAddDACL, 
                    (PSID)&pAce->SidStart, pAce->Mask, TRUE))
                {
                    // ��� ������ ��������� ����������
                    ETW::Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
                }
                break; 
            }
            // ��� ������������ �������� �������� �������
            case ACCESS_DENIED_ACE_TYPE: 
            {
                // ��������� �������������� ����
                PACCESS_DENIED_ACE pAce = (PACCESS_DENIED_ACE)pAceHeader; 

                // ���������� ����������� ������
                if (!::EventAccessControl(&guid, EventSecurityAddDACL, 
                    (PSID)&pAce->SidStart, pAce->Mask, FALSE))
                {
                    // ��� ������ ��������� ����������
                    ETW::Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
                }
                break; 
            }}
        }
        // ��� ���� ��������� ������ SACL
        if (pSacl) for (DWORD i = 0; i < pSacl->AceCount; i++)
        {
            // �������� ������� �������� �������
            PACE_HEADER pAceHeader = nullptr; if (!::GetAce(pSacl, i, (void**)&pAceHeader))
            {
                // ��� ������ ��������� ����������
                ETW::Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
            }
            switch (pAceHeader->AceType)
            {
            // ��� �������� ���������� ������
            case SYSTEM_AUDIT_ACE_TYPE: 
            {
                // ��������� �������������� ����
                PSYSTEM_AUDIT_ACE pAce = (PSYSTEM_AUDIT_ACE)pAceHeader; 

                // ���������� ����� �������
                if (!::EventAccessControl(&guid, EventSecurityAddSACL, 
                    (PSID)&pAce->SidStart, pAce->Mask, TRUE))
                {
                    // ��� ������ ��������� ����������
                    ETW::Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
                }
                break; 
            }}
        }
        return guid; 
    }
    // ��� ������ ��������� ����� ��������
    catch (...) { ::EventAccessRemove(&guid); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// ����� �����������
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<ETW::IEventLogger> ETW::EventLogger::Open(PCWSTR szName) 
{
    // �������� ����� ���������� �������
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR)] = {0}; 

    // ��������� �������������� ����
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // ������� ������ ���������
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // �������� �������� ������ �����������
    ULONG code = ::ControlTraceW(0, szName, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // ��������� ���������� ������
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // �������� ��������� ������
    TRACEHANDLE hTrace = pProperties->Wnode.HistoricalContext; BOOL legasySystem = FALSE; 

    // ���������� ����������� ������
    if (::lstrcmpiW(szName, KERNEL_LOGGER_NAMEW) == 0) legasySystem = TRUE; else 
    if (::lstrcmpiW(szName, GLOBAL_LOGGER_NAMEW) == 0)
    {
        // ��������� ����� ��������� ������� 
        if (pProperties->EnableFlags != 0) legasySystem = TRUE;  
    }
    // ��� ��������������� ������
    if ((pProperties->LogFileMode & EVENT_TRACE_BUFFERING_MODE) != 0)
    {
        // ������� ������ ��������������� ������
        return std::shared_ptr<IEventLogger>(
            new EventLogger(hTrace, szName, pProperties->LogFileMode, legasySystem)
        ); 
    }
    else {
        // ������� ������ ������ � �������������
        return std::shared_ptr<IEventLogger>((EventLogger*)
            new ConsumerLogger(hTrace, szName, pProperties->LogFileMode, legasySystem)
        ); 
    }
}

ETW::EventLogger::EventLogger(PSECURITY_DESCRIPTOR pSecurityDescriptor, PCWSTR szName, 
    ULONG mode, TimestampType timerType, const EVENT_LOGGER_PARAMS& parameters, PCWSTR szLogFile)

    // ��������� ���������� ���������
    : _timerType(timerType), _defaultSecurity(!pSecurityDescriptor)
{
    // ��������� ������������ ������������ ������
    if ((mode & EVENT_TRACE_BUFFERING_MODE) || !CheckSessionMode(mode)) 
    {
        // ��� ������ ��������� ����������
        Exception::Throw(E_INVALIDARG);
    }
    // ������� ������� ��������� ��������� �������
    _system = ((mode & EVENT_TRACE_SYSTEM_LOGGER_MODE) != 0); 

    // ���������� ����������� ������
    if (::lstrcmpiW(szName, KERNEL_LOGGER_NAMEW) == 0) _system = TRUE;

    // ��������� ������ ������
    GUID guid = _defaultSecurity ? GUID_NULL : CreateSessionSecurity(pSecurityDescriptor); 

    // �������� ����� ���������� �������
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 2048 * sizeof(WCHAR)] = {0}; 

    // ��������� �������������� ����
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // ������� ������ ���������
    pProperties->Wnode.BufferSize = sizeof(buffer); 
    
    // ������� �������� ����� ������
    pProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES); 

    // ������� ��� ��������� � ������������� ������
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; 

    // ������� ����� ������
    pProperties->LogFileMode = mode; pProperties->Wnode.Guid = guid; 
    
    // ������� ��� ������� 
    pProperties->Wnode.ClientContext = ConvertTimestampType(timerType);

    // ��� ������� ����� ���-�����
    if (szLogFile) { pProperties->MaximumFileSize = parameters.MaxLogFileSize; 
    
        // ������� �������� ����� �����
        pProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR); 

        // ��� ���������� ������������� ������� ���-�����
        if (pProperties->MaximumFileSize == 0)
        {
            // ��������� ������������ ������
            if (mode & EVENT_TRACE_FILE_MODE_CIRCULAR   ) Exception::Throw(E_INVALIDARG);
            if (mode & EVENT_TRACE_FILE_MODE_NEWFILE    ) Exception::Throw(E_INVALIDARG);
            if (mode & EVENT_TRACE_FILE_MODE_PREALLOCATE) Exception::Throw(E_INVALIDARG);
        }
        // ���������� ������ ����� ����� � ������
        size_t cbLogFileName = (wcslen(szLogFile) + 1) * sizeof(WCHAR); 

        // ��������� ������������ ����� �����
        if (cbLogFileName >= 1024 * sizeof(WCHAR)) Exception::Throw(E_INVALIDARG);

        // ����������� ��� �����
        memcpy((PBYTE)pProperties + pProperties->LogFileNameOffset, szLogFile, cbLogFileName); 
    }
    else {
        // ��������� ������� ������ ��������� �������
        if ((mode & EVENT_TRACE_REAL_TIME_MODE) == 0) Exception::Throw(E_INVALIDARG);

        // ��������� ������������ ������
        if (mode & EVENT_TRACE_FILE_MODE_SEQUENTIAL ) Exception::Throw(E_INVALIDARG);
        if (mode & EVENT_TRACE_FILE_MODE_CIRCULAR   ) Exception::Throw(E_INVALIDARG);
        if (mode & EVENT_TRACE_FILE_MODE_APPEND     ) Exception::Throw(E_INVALIDARG);
        if (mode & EVENT_TRACE_FILE_MODE_NEWFILE    ) Exception::Throw(E_INVALIDARG);
        if (mode & EVENT_TRACE_FILE_MODE_PREALLOCATE) Exception::Throw(E_INVALIDARG);

        // ������� ���������� ���-�����
        pProperties->LogFileNameOffset = 0; pProperties->MaximumFileSize = 0; 
    }
    // ������� ��� ��������� � ����� ������
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; pProperties->LogFileMode = mode;

    // ������� ��� �������
    pProperties->Wnode.ClientContext = ConvertTimestampType(timerType); 
    
    // ������� ��������� ������
    pProperties->BufferSize     = parameters.BufferSize; 
    pProperties->MinimumBuffers = parameters.MinimumBuffers; 
    pProperties->MaximumBuffers = parameters.MaximumBuffers; 
    pProperties->FlushTimer     = parameters.FlushTimer; 
    try { 
        // ����������� ��� ���-�����
        _bstrName = ::SysAllocString(szName); if (!_bstrName) Exception::Throw(E_OUTOFMEMORY);
        try { 
            // ������� �����
            ULONG code = ::StartTraceW(&_hTrace, szName, pProperties); 

            // ��������� ���������� ������
            if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

            // ��������� ������������� ������
            _guid = pProperties->Wnode.Guid; 
        }
        // ���������� ���������� �������
        catch (...) { ::SysFreeString(_bstrName); throw; }
    }
    // �������� ������ ������
    catch (...) { if (_defaultSecurity) ::EventAccessRemove(&guid); throw; }
}

ETW::EventLogger::EventLogger(PSECURITY_DESCRIPTOR pSecurityDescriptor, 
    PCWSTR szName, ULONG mode, TimestampType timerType, ULONG bufferSize)

    // ��������� ���������� ���������
    : _timerType(timerType), _defaultSecurity(!pSecurityDescriptor)
{
    // ��������� ������������ ������������ ������
    if (!CheckSessionMode(mode | EVENT_TRACE_BUFFERING_MODE)) Exception::Throw(E_INVALIDARG); 
    
    // ������� ������� ��������� ��������� �������
    _system = ((mode & EVENT_TRACE_SYSTEM_LOGGER_MODE) != 0); 

    // ���������� ����������� ������
    if (::lstrcmpiW(szName, KERNEL_LOGGER_NAMEW) == 0) _system = TRUE;

    // ��������� ������ ������
    GUID guid = _defaultSecurity ? GUID_NULL : CreateSessionSecurity(pSecurityDescriptor); 

    // �������� ���������� �� ������������ �������
    SYSTEM_INFO systemInfo; ::GetSystemInfo(&systemInfo); 

    // �������� ����� ���������� �������
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR)] = {0}; 

    // ��������� �������������� ����
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // ������� ������ ���������
    pProperties->Wnode.BufferSize = sizeof(buffer); 
    
    // ������� �������� ����� ������
    pProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES); 

    // ������� ��� ��������� � ������������� ������
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; pProperties->Wnode.Guid = guid; 

    // ������� ����� ������
    pProperties->LogFileMode = mode | EVENT_TRACE_BUFFERING_MODE; 
    
    // ������� ��� ������� 
    pProperties->Wnode.ClientContext = ConvertTimestampType(timerType); 

    // ������� ��������� �������
    pProperties->MinimumBuffers = systemInfo.dwNumberOfProcessors; 
    do {
        // ���������� ����������� ����� �������
        pProperties->MinimumBuffers *= 2; 

        // ���������� ������ ������
        pProperties->BufferSize = bufferSize / (1024 * pProperties->MinimumBuffers); 

        // ��� �������������
        if (pProperties->BufferSize * 1024 * pProperties->MinimumBuffers < bufferSize)
        {
            // ��������������� ������ ������
            pProperties->BufferSize++; 
        }
    }
    // ��������� ������ ������
    while (pProperties->BufferSize > 1024 * 1024); 

    // ������� ������������ ����� �������
    pProperties->MaximumBuffers = pProperties->MinimumBuffers; 
    try { 
        // ����������� ��� ���-�����
        _bstrName = ::SysAllocString(szName); if (!_bstrName) Exception::Throw(E_OUTOFMEMORY);
        try { 
            // ������� �����
            ULONG code = ::StartTraceW(&_hTrace, szName, pProperties); 

            // ��������� ���������� ������
            if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

            // ��������� ������������� ������
            _guid = pProperties->Wnode.Guid; 
        }
        // ���������� ���������� �������
        catch (...) { ::SysFreeString(_bstrName); throw; }
    }
    // �������� ������ ������
    catch (...) { if (_defaultSecurity) ::EventAccessRemove(&guid); throw; }
}

ETW::EventLogger::EventLogger(TRACEHANDLE hTrace, PCWSTR szName, ULONG mode, BOOL legacySystem)

    // ��������� ���������� ���������
    : _hTrace(hTrace), _defaultSecurity(TRUE)
{
    // ��������� ������������ ������������ ������
    if (!CheckSessionMode(mode)) Exception::Throw(E_INVALIDARG);
    
    // ������� ������� ��������� ��������� �������
    _system = ((mode & EVENT_TRACE_SYSTEM_LOGGER_MODE) != 0) || legacySystem; 

    // �������� ����� ���������� �������
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR)] = {0}; 

    // ��������� �������������� ����
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // ������� ������ ���������
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // �������� �������� ������ �����������
    ULONG code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // ��������� ���������� ������
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // ��������� ��� �������
    _timerType = ConvertTimestampType(pProperties->Wnode.ClientContext); 

    // ����������� ��� ���-�����
    _bstrName = ::SysAllocString(szName); _guid = pProperties->Wnode.Guid; 

    // ��������� ���������� ������
    if (!_bstrName) Exception::Throw(E_OUTOFMEMORY);
}

ETW::EventLogger::~EventLogger() { ::SysFreeString(_bstrName); 

    // �������� ������ ��� GUID
    if (!_defaultSecurity) ::EventAccessRemove(&_guid); 
}

void ETW::EventLogger::GetParameters(EVENT_BUFFER_PARAMS* pParameters) const
{
    // �������� ����� ���������� �������
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR)] = {0}; 

    // ��������� �������������� ����
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // ������� ������ ���������
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // �������� �������� ������ �����������
    ULONG code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // ��������� ���������� ������
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // ������� ��������� ������
    pParameters->BufferSize     = pProperties->BufferSize * 1024; 
    pParameters->MinimumBuffers = pProperties->MinimumBuffers; 
    pParameters->MaximumBuffers = pProperties->MaximumBuffers; 
}

static void SetSystemEnableFlags(TRACEHANDLE hTrace, ULONG flags, ULONG flagsMask)
{
    // �������� ����� ���������� �������
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR)] = {0}; 

    // ��������� �������������� ����
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // ������� ������ ���������
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // �������� �������� ������ �����������
    ULONG code = ::ControlTraceW(hTrace, nullptr, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // ��������� ���������� ������
    if (code != ERROR_SUCCESS) ETW::Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // �������������� ����� 
    ULONG enableFlags = (pProperties->EnableFlags & ~flagsMask) | flags;
    
    // ��������� ��������� ���������
    if (pProperties->EnableFlags == enableFlags) return; 

    // ������� ��� ���������
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; 

    // �������� ��� ��������� �������
    pProperties->EnableFlags = enableFlags; pProperties->LogFileNameOffset = 0; 

    // �������� ��������� ������ �����������
    code = ::ControlTraceW(hTrace, nullptr, pProperties, EVENT_TRACE_CONTROL_UPDATE); 

    // ��������� ���������� ������
    if (code != ERROR_SUCCESS) ETW::Exception::Throw(HRESULT_FROM_WIN32(code)); return; 
}

void ETW::EventLogger::EnableProvider(const GUID& guid, UCHAR level, ULONG matchAny, ULONG matchAll, ULONG properties) 
{
#if (WINVER >= _WIN32_WINNT_WIN6)
    if (!_system)
    {
        // �������� ��������� ��� �����������
        ULONG code = ::EnableTraceEx(&guid, &Guid(), Handle(), TRUE, level, matchAny, matchAll, properties, nullptr); 

        // ��������� ���������� ������
        if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); return; 
    }
#endif 
    UNREFERENCED_PARAMETER(properties); 

    // ��� �������� ���� �����
    if (matchAny != 0 && matchAll != 0) { matchAny = matchAll;
     
        // ��� ���� ����� �����
        for (size_t i = 0, bits = 0; i < sizeof(ULONG) * 8; i++)
        {
            // ���������� ����� ������������� �����
            if ((matchAll && (1UL << i)) == 0 || ++bits < 2) continue; 

            // ��� ���������� ���������� ��� ���� �����������������
            if (_system) { DisableProvider(guid); return; } else Exception::Throw(E_NOTIMPL); 
        }
    }
    // ���������� ���������
    EnableProvider(guid, level, matchAny); 
}

void ETW::EventLogger::EnableProvider(const GUID& guid, UCHAR level, ULONG flags)
{
    // ��� �������� ��������� ������� � ������� EnableFlags
    if (_system && InlineIsEqualGUID(guid, SystemTraceControlGuid))
    {
        // �������������� ����� ��������� �������
        SetSystemEnableFlags(Handle(), flags, flags); return; 
    }
    // ��� �������� ��������� �������
    if (_system) { PERFINFO_GROUPMASK mask = {0}; ULONG cb = 0; ULONG code = ERROR_INVALID_FUNCTION; 

        // �������� ����� ����� ��������� �������
        PERFINFO_GROUPMASK groupMask    = GetSystemTraceEnableFlags(guid, flags); 
        PERFINFO_GROUPMASK groupMaskAll = GetSystemTraceEnableFlags(guid); 

#if (WINVER >= _WIN32_WINNT_WIN8)
        // ������� ����� ���������������� ���������
        TRACE_INFO_CLASS infoClass = TraceSystemTraceEnableFlagsInfo; 

        // �������� ������� ����� ��������� �������
        code = ::TraceQueryInformation(Handle(), infoClass, &mask, sizeof(mask), &cb); 

        // ��� ���������� ������ 
        if (code == ERROR_SUCCESS) 
        { 
            // ��������� ����������� ���� �����
            for (ULONG i = 0; i < _countof(groupMask.Masks); i++) 
            {
                // ��������� ����������� ���� �����
                mask.Masks[i] &= ~groupMaskAll.Masks[i]; 
                mask.Masks[i] |=  groupMask   .Masks[i]; 
            }
            // �������������� ����� �����
            code = ::TraceSetInformation(Handle(), infoClass, &mask, sizeof(mask)); 
        }
#endif 
        if (code != ERROR_SUCCESS) 
        { 
            // �������� ��������� ������� � ������� EnableFlags
            ULONG enableFlags    = GetSystemLegacyEnableFlags(groupMask   ); 
            ULONG enableFlagsAll = GetSystemLegacyEnableFlags(groupMaskAll); 

            // �������������� ����� ��������� �������
            SetSystemEnableFlags(Handle(), enableFlags, enableFlagsAll);
        }
    }
    else {
        // �������� ��������� ��� �����������
        ULONG code = ::EnableTrace(TRUE, flags, level, &guid, Handle()); 

        // ��������� ���������� ������
        if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 
    }
}

void ETW::EventLogger::DisableProvider(const GUID& guid)
{
    // ��� �������� ��������� ������� � ������� EnableFlags
    if (_system && InlineIsEqualGUID(guid, SystemTraceControlGuid))
    {
        // �������������� ����� ��������� �������
        SetSystemEnableFlags(Handle(), 0, ULONG_MAX); return; 
    }
    // ��� �������� ��������� �������
    if (_system) { PERFINFO_GROUPMASK mask = {0}; ULONG cb = 0; ULONG code = ERROR_INVALID_FUNCTION; 

        // �������� ����� ����� ��������� �������
        PERFINFO_GROUPMASK groupMaskAll = GetSystemTraceEnableFlags(guid); 

#if (WINVER >= _WIN32_WINNT_WIN8)
        // ������� ����� ���������������� ���������
        TRACE_INFO_CLASS infoClass = TraceSystemTraceEnableFlagsInfo; 

        // �������� ������� ����� ��������� �������
        code = ::TraceQueryInformation(Handle(), infoClass, &mask, sizeof(mask), &cb); 

        // ��� ���������� ������ 
        if (code == ERROR_SUCCESS) { 

            // ������� ����� ����� �� �������
            for (ULONG i = 0; i < _countof(groupMaskAll.Masks); i++) 
            {
                // ������� ����� ����� �� �������
                mask.Masks[i] &= ~groupMaskAll.Masks[i]; 
            }
            // �������������� ����� �����
            code = ::TraceSetInformation(Handle(), infoClass, &mask, sizeof(mask)); 
        }
#endif 
        if (code != ERROR_SUCCESS) 
        { 
            // �������� ��������� ������� � ������� EnableFlags
            ULONG enableFlagsAll = GetSystemLegacyEnableFlags(groupMaskAll); 

            // �������������� ����� ��������� �������
            SetSystemEnableFlags(Handle(), 0, enableFlagsAll);
        }
    }
    else {
        // ������� ��������� �� �����������
        ULONG code = ::EnableTrace(FALSE, 0, 0, &guid, Handle()); 

        // ��������� ���������� ������
        if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 
    }
}

void ETW::EventLogger::Close()
{
    // �������� ����� ���������� �������
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR)] = {0}; 

    // ��������� �������������� ����
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // ������� ������ � ��� ���������
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // ������� ��� ���������
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; 

    // �������� ��������� ������ �����������
    ULONG code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_STOP); 

    // ��������� ���������� ������
    if (code != ERROR_SUCCESS) ETW::Exception::Throw(HRESULT_FROM_WIN32(code)); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� �����������, ��������� � ���-������� �/��� �������������
///////////////////////////////////////////////////////////////////////////////
ETW::ConsumerLogger::ConsumerLogger(PSECURITY_DESCRIPTOR pSecurityDescriptor, PCWSTR szName, 
    ULONG mode, TimestampType timerType, const EVENT_LOGGER_PARAMS& parameters, PCWSTR szLogFile) 
        
    // ��������� ���������� ���������
    : EventLogger(pSecurityDescriptor, szName, mode, timerType, parameters, szLogFile) 
{
    // ��������� ������������ �����
    _mode = CheckSessionMode(mode); 
}

ETW::ConsumerLogger::ConsumerLogger(TRACEHANDLE hTrace, PCWSTR szName, ULONG mode, BOOL legacySystem)

    // ��������� ���������� ���������
    : EventLogger(hTrace, szName, mode, legacySystem)
{
    // ��������� ������������ ������������ ������
    if (mode & EVENT_TRACE_BUFFERING_MODE) Exception::Throw(E_INVALIDARG);

    // ��������� ������������ �����
    _mode = CheckSessionMode(mode); 
}
        
void ETW::ConsumerLogger::GetParameters(EVENT_LOGGER_PARAMS* pParameters) const
{
    // �������� ����� ���������� �������
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR)] = {0}; 

    // ��������� �������������� ����
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // ������� ������ ���������
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // �������� �������� ������ �����������
    ULONG code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // ��������� ���������� ������
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // ����������� ��������� ������
    pParameters->BufferSize     = pProperties->BufferSize;
    pParameters->MinimumBuffers = pProperties->MinimumBuffers;
    pParameters->MaximumBuffers = pProperties->MaximumBuffers; 
    pParameters->FlushTimer     = pProperties->FlushTimer; 
    pParameters->MaxLogFileSize = pProperties->MaximumFileSize; 

    // ������ ������ � ����� ���������� � ����������
    pParameters->BufferSize *= 1024; pParameters->MaxLogFileSize *= 1024; 

    // � ����������� �� ������
    if (!(pProperties->LogFileMode & EVENT_TRACE_USE_KBYTES_FOR_SIZE)) 
    {
        // ������ ����� ���������� � ����������
        pParameters->MaxLogFileSize *= 1024; 
    }
}

void ETW::ConsumerLogger::GetStatistics(EVENT_LOGGER_STATS* pStatistics) const
{
    // �������� ����� ���������� �������
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR)] = {0}; 

    // ��������� �������������� ����
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // ������� ������ ���������
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // �������� �������� ������ �����������
    ULONG code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // ��������� ���������� ������
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // ����������� ���������� ������
    pStatistics->NumberOfBuffers        = pProperties->NumberOfBuffers    ;
    pStatistics->FreeBuffers            = pProperties->FreeBuffers        ;
    pStatistics->EventsLost             = pProperties->EventsLost         ;
    pStatistics->BuffersWritten         = pProperties->BuffersWritten     ;
    pStatistics->LogBuffersLost         = pProperties->LogBuffersLost     ;
    pStatistics->RealTimeBuffersLost    = pProperties->RealTimeBuffersLost;
}

void ETW::ConsumerLogger::SetMaxBuffers(ULONG maxBuffers)
{
    // �������� ����� ���������� �������
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR)] = {0}; 

    // ��������� �������������� ����
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // ������� ������ ���������
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // �������� �������� ������ �����������
    ULONG code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // ��������� ���������� ������
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // ��������� ��������� ���������
    if (pProperties->MaximumBuffers == maxBuffers) return; 

    // ������� ��� ���������
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; 

    // ���������� ������������ ����� �������
    pProperties->MaximumBuffers = maxBuffers; pProperties->LogFileNameOffset = 0; 

    // �������� ��������� ������ �����������
    code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_UPDATE); 

    // ��������� ���������� ������
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 
}

void ETW::ConsumerLogger::SetFlushTimer(ULONG secTimer)
{
    // �������� ����� ���������� �������
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR)] = {0}; 

    // ��������� �������������� ����
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // ������� ������ ���������
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // �������� �������� ������ �����������
    ULONG code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // ��������� ���������� ������
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // ��������� ��������� ���������
    if (pProperties->FlushTimer == secTimer) return; 

    // ������� ��� ���������
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; 

    // ���������� ����� ������ �������
    pProperties->FlushTimer = secTimer; pProperties->LogFileNameOffset = 0;

    // �������� ��������� ������ �����������
    code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_UPDATE); 

    // ��������� ���������� ������
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 
}

void ETW::ConsumerLogger::SetRealTimeMode(BOOL realTime)
{
    // �������� ����� ���������� �������
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR)] = {0}; 

    // ��������� �������������� ����
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // ������� ������ ���������
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // �������� �������� ������ �����������
    ULONG code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // ��������� ���������� ������
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // ��������� ��������� ���������
    if ( realTime && (pProperties->LogFileMode & EVENT_TRACE_REAL_TIME_MODE) != 0) return; 
    if (!realTime && (pProperties->LogFileMode & EVENT_TRACE_REAL_TIME_MODE) == 0) return; 
        
    // ������� ��� ���������
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; 

    // �������� �������� ����� �����
    pProperties->LogFileMode = 0; pProperties->LogFileNameOffset = 0;

    // ������� ����������� ����������� ������������
    if (realTime) pProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;

    // �������� ��������� ������ �����������
    code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_UPDATE); 

    // ��������� ���������� ������
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // ������� ����������� ����������� ������������
    if (realTime) _mode |= EVENT_TRACE_REAL_TIME_MODE; else _mode &= ~EVENT_TRACE_REAL_TIME_MODE; 
}

BSTR ETW::ConsumerLogger::GetLogFileName() const
{
    // �������� ����� ���������� �������
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 2048 * sizeof(WCHAR)] = {0}; 

    // ��������� �������������� ����
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // ������� ������ ���������
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // ������� �������� ����� ������ � ���-�����
    pProperties->LoggerNameOffset  = sizeof(EVENT_TRACE_PROPERTIES); 
    pProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR); 

    // �������� �������� ������ �����������
    ULONG code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // ��������� ���������� ������
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // ��������� ������� �����
    if (pProperties->LogFileNameOffset == 0) return nullptr; 

    // ��������� �������������� ����
    PCWSTR szCurrentFileName = (PCWSTR)((PBYTE)pProperties + pProperties->LogFileNameOffset); 

    // ����������� ��� ���-�����
    BSTR bstrLogFileName = ::SysAllocString(szCurrentFileName); 

    // ��������� ���������� ������
    if (!bstrLogFileName) Exception::Throw(E_OUTOFMEMORY); return bstrLogFileName; 
}

void ETW::ConsumerLogger::SetLogFileName(PCWSTR szFileName)
{
    // ���������� ������ ����� ����� � ������
    size_t cbFileName = (wcslen(szFileName) + 1) * sizeof(WCHAR); 

    // ��������� ������������ ����� �����
    if (cbFileName >= 1024 * sizeof(WCHAR)) Exception::Throw(E_INVALIDARG); 

    // �������� ����� ���������� �������
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 2048 * sizeof(WCHAR)] = {0}; 

    // ��������� �������������� ����
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // ������� ������ ���������
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // ������� �������� ����� ������ � ���-�����
    pProperties->LoggerNameOffset  = sizeof(EVENT_TRACE_PROPERTIES); 
    pProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR); 

    // �������� �������� ������ �����������
    ULONG code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // ��������� ���������� ������
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // ������� ��� ���������
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; 

    // ��� ������� ����� �����
    if (pProperties->LogFileNameOffset != 0)
    {
        // ��������� �������������� ����
        PWSTR szCurrentFileName = (PWSTR)((PBYTE)pProperties + pProperties->LogFileNameOffset); 

        // ��������� ��������� ���������
        if (::lstrcmpiW(szCurrentFileName, szFileName) == 0) return; 

        // ����������� ��� �����
        memcpy(szCurrentFileName, szFileName, cbFileName); 
    }
    else {
        // ������� �������� ����� ������ � ���-�����
        pProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR); 

        // ��������� �������������� ����
        PWSTR szCurrentFileName = (PWSTR)((PBYTE)pProperties + pProperties->LogFileNameOffset); 

        // ����������� ��� �����
        memcpy(szCurrentFileName, szFileName, cbFileName); 
    }
    // �������� ��������� ������ �����������
    code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_UPDATE); 

    // ��������� ���������� ������
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 
}

void ETW::ConsumerLogger::Flush()
{
    // �������� ����� ���������� �������
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 2048 * sizeof(WCHAR)] = {0}; 

    // ��������� �������������� ����
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // ������� ������ ���������
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // ������� �������� ����� ������ � ���-�����
    pProperties->LoggerNameOffset  = sizeof(EVENT_TRACE_PROPERTIES); 
    pProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR); 

    // �������� �������� ������ �����������
    ULONG code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // ��������� ���������� ������
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // ������� ��� ���������
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; 

    // ����������� ��� ������
    memcpy(pProperties + 1, Name(), (wcslen(Name()) + 1) * sizeof(WCHAR)); 

    // �������� ������ � ���-���� ��� ������������
    code = ::ControlTraceW(Handle(), Name(), pProperties, EVENT_TRACE_CONTROL_FLUSH); 

    // ��������� ���������� ������
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 
}
