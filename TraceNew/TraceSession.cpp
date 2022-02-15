#include "TraceSession.hpp"
#include "TraceProvider.h"
#include "TraceETW.hpp"

///////////////////////////////////////////////////////////////////////////////
// Проверить корректность режима 
///////////////////////////////////////////////////////////////////////////////
static ULONG CheckSessionMode(ULONG mode)
{
    // для внутренного использования операционной системы
    if (mode & EVENT_TRACE_DELAY_OPEN_FILE_MODE) return 0; 
    if (mode & EVENT_TRACE_ADD_HEADER_MODE     ) return 0; 
    if (mode & EVENT_TRACE_RELOG_MODE          ) return 0; 

    // размер в параметрах всегда передается в байтах
    if (mode & EVENT_TRACE_USE_KBYTES_FOR_SIZE) return 0; 

    // проверить взаимоисключающие режимы
    if ((mode & EVENT_TRACE_USE_GLOBAL_SEQUENCE) &&
        (mode & EVENT_TRACE_USE_LOCAL_SEQUENCE )) return 0; 

    // для буферизованного режима
    if (mode & EVENT_TRACE_BUFFERING_MODE)
    {
        // проверить корректность параметров
        if (mode & EVENT_TRACE_FILE_MODE_CIRCULAR   ) return 0; 
        if (mode & EVENT_TRACE_FILE_MODE_SEQUENTIAL ) return 0; 
        if (mode & EVENT_TRACE_FILE_MODE_NEWFILE    ) return 0; 
        if (mode & EVENT_TRACE_FILE_MODE_APPEND     ) return 0; 
        if (mode & EVENT_TRACE_FILE_MODE_PREALLOCATE) return 0; 
        if (mode & EVENT_TRACE_REAL_TIME_MODE       ) return 0;

        // вернуть используемый режим
        return EVENT_TRACE_BUFFERING_MODE; 
    }
    // в режиме реального времени
    if (mode & EVENT_TRACE_REAL_TIME_MODE)
    {
        // проверить корректность параметров
        if (mode & EVENT_TRACE_FILE_MODE_APPEND) return 0; 
    }
    // для циклического заполнения файла
    if (mode & EVENT_TRACE_FILE_MODE_CIRCULAR)
    {
        // проверить корректность параметров
        if (mode & EVENT_TRACE_FILE_MODE_SEQUENTIAL) return 0; 
        if (mode & EVENT_TRACE_FILE_MODE_NEWFILE   ) return 0; 
        if (mode & EVENT_TRACE_FILE_MODE_APPEND    ) return 0; 

        // вернуть используемый режим
        return EVENT_TRACE_FILE_MODE_CIRCULAR | (mode & EVENT_TRACE_REAL_TIME_MODE); 
    }
    // для последовательного заполнения нескольких файлов
    else if (mode & EVENT_TRACE_FILE_MODE_NEWFILE)
    {
        // проверить корректность параметров
        if (mode & EVENT_TRACE_FILE_MODE_CIRCULAR  ) return 0; 
        if (mode & EVENT_TRACE_FILE_MODE_SEQUENTIAL) return 0; 
        if (mode & EVENT_TRACE_FILE_MODE_APPEND    ) return 0; 

        // вернуть используемый режим
        return EVENT_TRACE_FILE_MODE_NEWFILE | (mode & EVENT_TRACE_REAL_TIME_MODE); 
    }
    else {
        // проверить корректность параметров
        if (mode & EVENT_TRACE_FILE_MODE_CIRCULAR  ) return 0; 
        if (mode & EVENT_TRACE_FILE_MODE_NEWFILE   ) return 0; 

        // вернуть используемый режим
        return EVENT_TRACE_FILE_MODE_SEQUENTIAL | (mode & EVENT_TRACE_REAL_TIME_MODE); 
    }
}

///////////////////////////////////////////////////////////////////////////////
// Преобразовать тип таймера
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
// Настроить защиту сеанса
///////////////////////////////////////////////////////////////////////////////
static GUID CreateSessionSecurity(PSECURITY_DESCRIPTOR pSecurityDescriptor) 
{
    // проверить наличие дескриптора защиты
    GUID guid = GUID_NULL; if (!pSecurityDescriptor) return guid; 

    // создать уникальный идентификатор
    RPC_STATUS status = ::UuidCreate(&guid); if (status != RPC_S_OK) 
    {
        // проверить отсутствие ошибок
        ETW::Exception::Throw(HRESULT_FROM_WIN32(status)); 
    }
    // инициализировать переменные
    PACL pDacl = nullptr; BOOL daclPresent = FALSE; BOOL daclDefaulted = FALSE; 
    PACL pSacl = nullptr; BOOL saclPresent = FALSE; BOOL saclDefaulted = FALSE; 

    // получить список DACL
    if (!::GetSecurityDescriptorDacl(
        pSecurityDescriptor, &daclPresent, &pDacl, &daclDefaulted))
    {
        // при ошибке выбросить исключение
        ETW::Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
    }
    // получить список DACL
    if (!::GetSecurityDescriptorSacl(
        pSecurityDescriptor, &saclPresent, &pSacl, &saclDefaulted))
    {
        // при ошибке выбросить исключение
        ETW::Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
    }
    try { 
        // для всех элементов списка DACL
        if (pDacl) for (DWORD i = 0; i < pDacl->AceCount; i++)
        {
            // получить элемент контроля доступа
            PACE_HEADER pAceHeader = nullptr; if (!::GetAce(pDacl, i, (void**)&pAceHeader))
            {
                // при ошибке выбросить исключение
                ETW::Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
            }
            switch (pAceHeader->AceType)
            {
            // для разрешающего элемента контроля доступа
            case ACCESS_ALLOWED_ACE_TYPE: 
            {
                // выполнить преобразование типа
                PACCESS_ALLOWED_ACE pAce = (PACCESS_ALLOWED_ACE)pAceHeader; 

                // установить разрешающий доступ
                if (!::EventAccessControl(&guid, EventSecurityAddDACL, 
                    (PSID)&pAce->SidStart, pAce->Mask, TRUE))
                {
                    // при ошибке выбросить исключение
                    ETW::Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
                }
                break; 
            }
            // для запрещающего элемента контроля доступа
            case ACCESS_DENIED_ACE_TYPE: 
            {
                // выполнить преобразование типа
                PACCESS_DENIED_ACE pAce = (PACCESS_DENIED_ACE)pAceHeader; 

                // установить запрещающий доступ
                if (!::EventAccessControl(&guid, EventSecurityAddDACL, 
                    (PSID)&pAce->SidStart, pAce->Mask, FALSE))
                {
                    // при ошибке выбросить исключение
                    ETW::Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
                }
                break; 
            }}
        }
        // для всех элементов списка SACL
        if (pSacl) for (DWORD i = 0; i < pSacl->AceCount; i++)
        {
            // получить элемент контроля доступа
            PACE_HEADER pAceHeader = nullptr; if (!::GetAce(pSacl, i, (void**)&pAceHeader))
            {
                // при ошибке выбросить исключение
                ETW::Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
            }
            switch (pAceHeader->AceType)
            {
            // для элемента системного аудита
            case SYSTEM_AUDIT_ACE_TYPE: 
            {
                // выполнить преобразование типа
                PSYSTEM_AUDIT_ACE pAce = (PSYSTEM_AUDIT_ACE)pAceHeader; 

                // установить аудит доступа
                if (!::EventAccessControl(&guid, EventSecurityAddSACL, 
                    (PSID)&pAce->SidStart, pAce->Mask, TRUE))
                {
                    // при ошибке выбросить исключение
                    ETW::Exception::Throw(HRESULT_FROM_WIN32(::GetLastError())); 
                }
                break; 
            }}
        }
        return guid; 
    }
    // при ошибке выполнить откат операции
    catch (...) { ::EventAccessRemove(&guid); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// Сеанс трассировки
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<ETW::IEventLogger> ETW::EventLogger::Open(PCWSTR szName) 
{
    // выделить буфер требуемого размера
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR)] = {0}; 

    // выполнить преобразование типа
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // указать размер структуры
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // получить свойства сеанса трассировки
    ULONG code = ::ControlTraceW(0, szName, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // получить описатель сеанса
    TRACEHANDLE hTrace = pProperties->Wnode.HistoricalContext; BOOL legasySystem = FALSE; 

    // обработать специальные случаи
    if (::lstrcmpiW(szName, KERNEL_LOGGER_NAMEW) == 0) legasySystem = TRUE; else 
    if (::lstrcmpiW(szName, GLOBAL_LOGGER_NAMEW) == 0)
    {
        // проверить прием системных событий 
        if (pProperties->EnableFlags != 0) legasySystem = TRUE;  
    }
    // для буферизованного сеанса
    if ((pProperties->LogFileMode & EVENT_TRACE_BUFFERING_MODE) != 0)
    {
        // создать объект буферизованного сеанса
        return std::shared_ptr<IEventLogger>(
            new EventLogger(hTrace, szName, pProperties->LogFileMode, legasySystem)
        ); 
    }
    else {
        // создать объект сеанса с потребителями
        return std::shared_ptr<IEventLogger>((EventLogger*)
            new ConsumerLogger(hTrace, szName, pProperties->LogFileMode, legasySystem)
        ); 
    }
}

ETW::EventLogger::EventLogger(PSECURITY_DESCRIPTOR pSecurityDescriptor, PCWSTR szName, 
    ULONG mode, TimestampType timerType, const EVENT_LOGGER_PARAMS& parameters, PCWSTR szLogFile)

    // сохранить переданные параметры
    : _timerType(timerType), _defaultSecurity(!pSecurityDescriptor)
{
    // проверить корректность передаваемых флагов
    if ((mode & EVENT_TRACE_BUFFERING_MODE) || !CheckSessionMode(mode)) 
    {
        // при ошибке выбросить исключение
        Exception::Throw(E_INVALIDARG);
    }
    // указать признак получения системных событий
    _system = ((mode & EVENT_TRACE_SYSTEM_LOGGER_MODE) != 0); 

    // обработать специальный случай
    if (::lstrcmpiW(szName, KERNEL_LOGGER_NAMEW) == 0) _system = TRUE;

    // настроить защиту сеанса
    GUID guid = _defaultSecurity ? GUID_NULL : CreateSessionSecurity(pSecurityDescriptor); 

    // выделить буфер требуемого размера
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 2048 * sizeof(WCHAR)] = {0}; 

    // выполнить преобразование типа
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // указать размер структуры
    pProperties->Wnode.BufferSize = sizeof(buffer); 
    
    // указать смещение имени сеанса
    pProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES); 

    // указать тип структуры и идентификатор сеанса
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; 

    // указать режим сеанса
    pProperties->LogFileMode = mode; pProperties->Wnode.Guid = guid; 
    
    // указать тип таймера 
    pProperties->Wnode.ClientContext = ConvertTimestampType(timerType);

    // при наличии имени лог-файла
    if (szLogFile) { pProperties->MaximumFileSize = parameters.MaxLogFileSize; 
    
        // указать смещение имени файла
        pProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR); 

        // при отсутствии максимального размера лог-файла
        if (pProperties->MaximumFileSize == 0)
        {
            // проверить корректность режима
            if (mode & EVENT_TRACE_FILE_MODE_CIRCULAR   ) Exception::Throw(E_INVALIDARG);
            if (mode & EVENT_TRACE_FILE_MODE_NEWFILE    ) Exception::Throw(E_INVALIDARG);
            if (mode & EVENT_TRACE_FILE_MODE_PREALLOCATE) Exception::Throw(E_INVALIDARG);
        }
        // определить размер имени файла в байтах
        size_t cbLogFileName = (wcslen(szLogFile) + 1) * sizeof(WCHAR); 

        // проверить корректность имени файла
        if (cbLogFileName >= 1024 * sizeof(WCHAR)) Exception::Throw(E_INVALIDARG);

        // скопировать имя файла
        memcpy((PBYTE)pProperties + pProperties->LogFileNameOffset, szLogFile, cbLogFileName); 
    }
    else {
        // проверить наличие режима реального времени
        if ((mode & EVENT_TRACE_REAL_TIME_MODE) == 0) Exception::Throw(E_INVALIDARG);

        // проверить корректность режима
        if (mode & EVENT_TRACE_FILE_MODE_SEQUENTIAL ) Exception::Throw(E_INVALIDARG);
        if (mode & EVENT_TRACE_FILE_MODE_CIRCULAR   ) Exception::Throw(E_INVALIDARG);
        if (mode & EVENT_TRACE_FILE_MODE_APPEND     ) Exception::Throw(E_INVALIDARG);
        if (mode & EVENT_TRACE_FILE_MODE_NEWFILE    ) Exception::Throw(E_INVALIDARG);
        if (mode & EVENT_TRACE_FILE_MODE_PREALLOCATE) Exception::Throw(E_INVALIDARG);

        // указать отсутствие лог-файла
        pProperties->LogFileNameOffset = 0; pProperties->MaximumFileSize = 0; 
    }
    // указать тип структуры и режим сеанса
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; pProperties->LogFileMode = mode;

    // указать тип таймера
    pProperties->Wnode.ClientContext = ConvertTimestampType(timerType); 
    
    // указать параметры сеанса
    pProperties->BufferSize     = parameters.BufferSize; 
    pProperties->MinimumBuffers = parameters.MinimumBuffers; 
    pProperties->MaximumBuffers = parameters.MaximumBuffers; 
    pProperties->FlushTimer     = parameters.FlushTimer; 
    try { 
        // скопировать имя лог-файла
        _bstrName = ::SysAllocString(szName); if (!_bstrName) Exception::Throw(E_OUTOFMEMORY);
        try { 
            // создать сеанс
            ULONG code = ::StartTraceW(&_hTrace, szName, pProperties); 

            // проверить отсутствие ошибок
            if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

            // сохранить идентификатор сеанса
            _guid = pProperties->Wnode.Guid; 
        }
        // освободить выделенные ресурсы
        catch (...) { ::SysFreeString(_bstrName); throw; }
    }
    // отменить защиту сеанса
    catch (...) { if (_defaultSecurity) ::EventAccessRemove(&guid); throw; }
}

ETW::EventLogger::EventLogger(PSECURITY_DESCRIPTOR pSecurityDescriptor, 
    PCWSTR szName, ULONG mode, TimestampType timerType, ULONG bufferSize)

    // сохранить переданные параметры
    : _timerType(timerType), _defaultSecurity(!pSecurityDescriptor)
{
    // проверить корректность передаваемых флагов
    if (!CheckSessionMode(mode | EVENT_TRACE_BUFFERING_MODE)) Exception::Throw(E_INVALIDARG); 
    
    // указать признак получения системных событий
    _system = ((mode & EVENT_TRACE_SYSTEM_LOGGER_MODE) != 0); 

    // обработать специальный случай
    if (::lstrcmpiW(szName, KERNEL_LOGGER_NAMEW) == 0) _system = TRUE;

    // настроить защиту сеанса
    GUID guid = _defaultSecurity ? GUID_NULL : CreateSessionSecurity(pSecurityDescriptor); 

    // получить информацию от операционной системы
    SYSTEM_INFO systemInfo; ::GetSystemInfo(&systemInfo); 

    // выделить буфер требуемого размера
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR)] = {0}; 

    // выполнить преобразование типа
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // указать размер структуры
    pProperties->Wnode.BufferSize = sizeof(buffer); 
    
    // указать смещение имени сеанса
    pProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES); 

    // указать тип структуры и идентификатор сеанса
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; pProperties->Wnode.Guid = guid; 

    // указать режим сеанса
    pProperties->LogFileMode = mode | EVENT_TRACE_BUFFERING_MODE; 
    
    // указать тип таймера 
    pProperties->Wnode.ClientContext = ConvertTimestampType(timerType); 

    // указать начальные условия
    pProperties->MinimumBuffers = systemInfo.dwNumberOfProcessors; 
    do {
        // определить минимальное число буферов
        pProperties->MinimumBuffers *= 2; 

        // определить размер буфера
        pProperties->BufferSize = bufferSize / (1024 * pProperties->MinimumBuffers); 

        // при необходимости
        if (pProperties->BufferSize * 1024 * pProperties->MinimumBuffers < bufferSize)
        {
            // скорректировать размер буфера
            pProperties->BufferSize++; 
        }
    }
    // проверить размер буфера
    while (pProperties->BufferSize > 1024 * 1024); 

    // указать максимальное число буферов
    pProperties->MaximumBuffers = pProperties->MinimumBuffers; 
    try { 
        // скопировать имя лог-файла
        _bstrName = ::SysAllocString(szName); if (!_bstrName) Exception::Throw(E_OUTOFMEMORY);
        try { 
            // создать сеанс
            ULONG code = ::StartTraceW(&_hTrace, szName, pProperties); 

            // проверить отсутствие ошибок
            if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

            // сохранить идентификатор сеанса
            _guid = pProperties->Wnode.Guid; 
        }
        // освободить выделенные ресурсы
        catch (...) { ::SysFreeString(_bstrName); throw; }
    }
    // отменить защиту сеанса
    catch (...) { if (_defaultSecurity) ::EventAccessRemove(&guid); throw; }
}

ETW::EventLogger::EventLogger(TRACEHANDLE hTrace, PCWSTR szName, ULONG mode, BOOL legacySystem)

    // сохранить переданные параметры
    : _hTrace(hTrace), _defaultSecurity(TRUE)
{
    // проверить корректность передаваемых флагов
    if (!CheckSessionMode(mode)) Exception::Throw(E_INVALIDARG);
    
    // указать признак получения системных событий
    _system = ((mode & EVENT_TRACE_SYSTEM_LOGGER_MODE) != 0) || legacySystem; 

    // выделить буфер требуемого размера
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR)] = {0}; 

    // выполнить преобразование типа
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // указать размер структуры
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // получить свойства сеанса трассировки
    ULONG code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // сохранить тип таймера
    _timerType = ConvertTimestampType(pProperties->Wnode.ClientContext); 

    // скопировать имя лог-файла
    _bstrName = ::SysAllocString(szName); _guid = pProperties->Wnode.Guid; 

    // проверить отсутствие ошибок
    if (!_bstrName) Exception::Throw(E_OUTOFMEMORY);
}

ETW::EventLogger::~EventLogger() { ::SysFreeString(_bstrName); 

    // отменить защиту для GUID
    if (!_defaultSecurity) ::EventAccessRemove(&_guid); 
}

void ETW::EventLogger::GetParameters(EVENT_BUFFER_PARAMS* pParameters) const
{
    // выделить буфер требуемого размера
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR)] = {0}; 

    // выполнить преобразование типа
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // указать размер структуры
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // получить свойства сеанса трассировки
    ULONG code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // вернуть параметры сеанса
    pParameters->BufferSize     = pProperties->BufferSize * 1024; 
    pParameters->MinimumBuffers = pProperties->MinimumBuffers; 
    pParameters->MaximumBuffers = pProperties->MaximumBuffers; 
}

static void SetSystemEnableFlags(TRACEHANDLE hTrace, ULONG flags, ULONG flagsMask)
{
    // выделить буфер требуемого размера
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR)] = {0}; 

    // выполнить преобразование типа
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // указать размер структуры
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // получить свойства сеанса трассировки
    ULONG code = ::ControlTraceW(hTrace, nullptr, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) ETW::Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // переустановить флаги 
    ULONG enableFlags = (pProperties->EnableFlags & ~flagsMask) | flags;
    
    // проверить изменение параметра
    if (pProperties->EnableFlags == enableFlags) return; 

    // указать тип структуры
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; 

    // сбросить все системные события
    pProperties->EnableFlags = enableFlags; pProperties->LogFileNameOffset = 0; 

    // изменить параметры сеанса трассировки
    code = ::ControlTraceW(hTrace, nullptr, pProperties, EVENT_TRACE_CONTROL_UPDATE); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) ETW::Exception::Throw(HRESULT_FROM_WIN32(code)); return; 
}

void ETW::EventLogger::EnableProvider(const GUID& guid, UCHAR level, ULONG matchAny, ULONG matchAll, ULONG properties) 
{
#if (WINVER >= _WIN32_WINNT_WIN6)
    if (!_system)
    {
        // добавить провайдер для трассировки
        ULONG code = ::EnableTraceEx(&guid, &Guid(), Handle(), TRUE, level, matchAny, matchAll, properties, nullptr); 

        // проверить отсутствие ошибок
        if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); return; 
    }
#endif 
    UNREFERENCED_PARAMETER(properties); 

    // при указании двух масок
    if (matchAny != 0 && matchAll != 0) { matchAny = matchAll;
     
        // для всех битов маски
        for (size_t i = 0, bits = 0; i < sizeof(ULONG) * 8; i++)
        {
            // подсчитать число установленных битов
            if ((matchAll && (1UL << i)) == 0 || ++bits < 2) continue; 

            // для системного провайдера все биты взаимоисключающие
            if (_system) { DisableProvider(guid); return; } else Exception::Throw(E_NOTIMPL); 
        }
    }
    // подключить провайдер
    EnableProvider(guid, level, matchAny); 
}

void ETW::EventLogger::EnableProvider(const GUID& guid, UCHAR level, ULONG flags)
{
    // при указании системных событий в формате EnableFlags
    if (_system && InlineIsEqualGUID(guid, SystemTraceControlGuid))
    {
        // переустановить маску системных событий
        SetSystemEnableFlags(Handle(), flags, flags); return; 
    }
    // при указании системных событий
    if (_system) { PERFINFO_GROUPMASK mask = {0}; ULONG cb = 0; ULONG code = ERROR_INVALID_FUNCTION; 

        // получить новую маску системных событий
        PERFINFO_GROUPMASK groupMask    = GetSystemTraceEnableFlags(guid, flags); 
        PERFINFO_GROUPMASK groupMaskAll = GetSystemTraceEnableFlags(guid); 

#if (WINVER >= _WIN32_WINNT_WIN8)
        // указать класс устанавливаемого параметра
        TRACE_INFO_CLASS infoClass = TraceSystemTraceEnableFlagsInfo; 

        // получить текущую маску системных событий
        code = ::TraceQueryInformation(Handle(), infoClass, &mask, sizeof(mask), &cb); 

        // при отсутствии ошибок 
        if (code == ERROR_SUCCESS) 
        { 
            // выполнить объединение двух маоск
            for (ULONG i = 0; i < _countof(groupMask.Masks); i++) 
            {
                // выполнить объединение двух маоск
                mask.Masks[i] &= ~groupMaskAll.Masks[i]; 
                mask.Masks[i] |=  groupMask   .Masks[i]; 
            }
            // переустановить новую маску
            code = ::TraceSetInformation(Handle(), infoClass, &mask, sizeof(mask)); 
        }
#endif 
        if (code != ERROR_SUCCESS) 
        { 
            // получить системные события в формате EnableFlags
            ULONG enableFlags    = GetSystemLegacyEnableFlags(groupMask   ); 
            ULONG enableFlagsAll = GetSystemLegacyEnableFlags(groupMaskAll); 

            // переустановить маску системных событий
            SetSystemEnableFlags(Handle(), enableFlags, enableFlagsAll);
        }
    }
    else {
        // добавить провайдер для трассировки
        ULONG code = ::EnableTrace(TRUE, flags, level, &guid, Handle()); 

        // проверить отсутствие ошибок
        if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 
    }
}

void ETW::EventLogger::DisableProvider(const GUID& guid)
{
    // при указании системных событий в формате EnableFlags
    if (_system && InlineIsEqualGUID(guid, SystemTraceControlGuid))
    {
        // переустановить маску системных событий
        SetSystemEnableFlags(Handle(), 0, ULONG_MAX); return; 
    }
    // при указании системных событий
    if (_system) { PERFINFO_GROUPMASK mask = {0}; ULONG cb = 0; ULONG code = ERROR_INVALID_FUNCTION; 

        // получить новую маску системных событий
        PERFINFO_GROUPMASK groupMaskAll = GetSystemTraceEnableFlags(guid); 

#if (WINVER >= _WIN32_WINNT_WIN8)
        // указать класс устанавливаемого параметра
        TRACE_INFO_CLASS infoClass = TraceSystemTraceEnableFlagsInfo; 

        // получить текущую маску системных событий
        code = ::TraceQueryInformation(Handle(), infoClass, &mask, sizeof(mask), &cb); 

        // при отсутствии ошибок 
        if (code == ERROR_SUCCESS) { 

            // удалить новую маску из текущей
            for (ULONG i = 0; i < _countof(groupMaskAll.Masks); i++) 
            {
                // удалить новую маску из текущей
                mask.Masks[i] &= ~groupMaskAll.Masks[i]; 
            }
            // переустановить новую маску
            code = ::TraceSetInformation(Handle(), infoClass, &mask, sizeof(mask)); 
        }
#endif 
        if (code != ERROR_SUCCESS) 
        { 
            // получить системные события в формате EnableFlags
            ULONG enableFlagsAll = GetSystemLegacyEnableFlags(groupMaskAll); 

            // переустановить маску системных событий
            SetSystemEnableFlags(Handle(), 0, enableFlagsAll);
        }
    }
    else {
        // удалить провайдер из трассировки
        ULONG code = ::EnableTrace(FALSE, 0, 0, &guid, Handle()); 

        // проверить отсутствие ошибок
        if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 
    }
}

void ETW::EventLogger::Close()
{
    // выделить буфер требуемого размера
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR)] = {0}; 

    // выполнить преобразование типа
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // указать размер и тип структуры
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // указать тип структуры
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; 

    // изменить параметры сеанса трассировки
    ULONG code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_STOP); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) ETW::Exception::Throw(HRESULT_FROM_WIN32(code)); 
}

///////////////////////////////////////////////////////////////////////////////
// Сеанс трассировки, связанный с лог-файлами и/или потребителями
///////////////////////////////////////////////////////////////////////////////
ETW::ConsumerLogger::ConsumerLogger(PSECURITY_DESCRIPTOR pSecurityDescriptor, PCWSTR szName, 
    ULONG mode, TimestampType timerType, const EVENT_LOGGER_PARAMS& parameters, PCWSTR szLogFile) 
        
    // сохранить переданные параметры
    : EventLogger(pSecurityDescriptor, szName, mode, timerType, parameters, szLogFile) 
{
    // сохранить используемый режим
    _mode = CheckSessionMode(mode); 
}

ETW::ConsumerLogger::ConsumerLogger(TRACEHANDLE hTrace, PCWSTR szName, ULONG mode, BOOL legacySystem)

    // сохранить переданные параметры
    : EventLogger(hTrace, szName, mode, legacySystem)
{
    // проверить корректность передаваемых флагов
    if (mode & EVENT_TRACE_BUFFERING_MODE) Exception::Throw(E_INVALIDARG);

    // сохранить используемый режим
    _mode = CheckSessionMode(mode); 
}
        
void ETW::ConsumerLogger::GetParameters(EVENT_LOGGER_PARAMS* pParameters) const
{
    // выделить буфер требуемого размера
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR)] = {0}; 

    // выполнить преобразование типа
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // указать размер структуры
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // получить свойства сеанса трассировки
    ULONG code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // скопировать параметры сеанса
    pParameters->BufferSize     = pProperties->BufferSize;
    pParameters->MinimumBuffers = pProperties->MinimumBuffers;
    pParameters->MaximumBuffers = pProperties->MaximumBuffers; 
    pParameters->FlushTimer     = pProperties->FlushTimer; 
    pParameters->MaxLogFileSize = pProperties->MaximumFileSize; 

    // размер буфера и файла измеряется в килобайтах
    pParameters->BufferSize *= 1024; pParameters->MaxLogFileSize *= 1024; 

    // в зависимости от режима
    if (!(pProperties->LogFileMode & EVENT_TRACE_USE_KBYTES_FOR_SIZE)) 
    {
        // размер файла измеряется в мегабайтах
        pParameters->MaxLogFileSize *= 1024; 
    }
}

void ETW::ConsumerLogger::GetStatistics(EVENT_LOGGER_STATS* pStatistics) const
{
    // выделить буфер требуемого размера
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR)] = {0}; 

    // выполнить преобразование типа
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // указать размер структуры
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // получить свойства сеанса трассировки
    ULONG code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // скопировать статистику сеанса
    pStatistics->NumberOfBuffers        = pProperties->NumberOfBuffers    ;
    pStatistics->FreeBuffers            = pProperties->FreeBuffers        ;
    pStatistics->EventsLost             = pProperties->EventsLost         ;
    pStatistics->BuffersWritten         = pProperties->BuffersWritten     ;
    pStatistics->LogBuffersLost         = pProperties->LogBuffersLost     ;
    pStatistics->RealTimeBuffersLost    = pProperties->RealTimeBuffersLost;
}

void ETW::ConsumerLogger::SetMaxBuffers(ULONG maxBuffers)
{
    // выделить буфер требуемого размера
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR)] = {0}; 

    // выполнить преобразование типа
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // указать размер структуры
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // получить свойства сеанса трассировки
    ULONG code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // проверить изменение параметра
    if (pProperties->MaximumBuffers == maxBuffers) return; 

    // указать тип структуры
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; 

    // установить максимальное число буферов
    pProperties->MaximumBuffers = maxBuffers; pProperties->LogFileNameOffset = 0; 

    // изменить параметры сеанса трассировки
    code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_UPDATE); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 
}

void ETW::ConsumerLogger::SetFlushTimer(ULONG secTimer)
{
    // выделить буфер требуемого размера
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR)] = {0}; 

    // выполнить преобразование типа
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // указать размер структуры
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // получить свойства сеанса трассировки
    ULONG code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // проверить изменение параметра
    if (pProperties->FlushTimer == secTimer) return; 

    // указать тип структуры
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; 

    // установить время сброса буферов
    pProperties->FlushTimer = secTimer; pProperties->LogFileNameOffset = 0;

    // изменить параметры сеанса трассировки
    code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_UPDATE); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 
}

void ETW::ConsumerLogger::SetRealTimeMode(BOOL realTime)
{
    // выделить буфер требуемого размера
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR)] = {0}; 

    // выполнить преобразование типа
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // указать размер структуры
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // получить свойства сеанса трассировки
    ULONG code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // проверить изменение параметра
    if ( realTime && (pProperties->LogFileMode & EVENT_TRACE_REAL_TIME_MODE) != 0) return; 
    if (!realTime && (pProperties->LogFileMode & EVENT_TRACE_REAL_TIME_MODE) == 0) return; 
        
    // указать тип структуры
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; 

    // отменить указание имени файла
    pProperties->LogFileMode = 0; pProperties->LogFileNameOffset = 0;

    // указать возможность подключения потребителей
    if (realTime) pProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;

    // изменить параметры сеанса трассировки
    code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_UPDATE); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // указать возможность подключения потребителей
    if (realTime) _mode |= EVENT_TRACE_REAL_TIME_MODE; else _mode &= ~EVENT_TRACE_REAL_TIME_MODE; 
}

BSTR ETW::ConsumerLogger::GetLogFileName() const
{
    // выделить буфер требуемого размера
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 2048 * sizeof(WCHAR)] = {0}; 

    // выполнить преобразование типа
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // указать размер структуры
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // указать смещение имени сеанса и лог-файла
    pProperties->LoggerNameOffset  = sizeof(EVENT_TRACE_PROPERTIES); 
    pProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR); 

    // получить свойства сеанса трассировки
    ULONG code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // проверить наличие файла
    if (pProperties->LogFileNameOffset == 0) return nullptr; 

    // выполнить преобразование типа
    PCWSTR szCurrentFileName = (PCWSTR)((PBYTE)pProperties + pProperties->LogFileNameOffset); 

    // скопировать имя лог-файла
    BSTR bstrLogFileName = ::SysAllocString(szCurrentFileName); 

    // проверить отсутствие ошибок
    if (!bstrLogFileName) Exception::Throw(E_OUTOFMEMORY); return bstrLogFileName; 
}

void ETW::ConsumerLogger::SetLogFileName(PCWSTR szFileName)
{
    // определить размер имени файла в байтах
    size_t cbFileName = (wcslen(szFileName) + 1) * sizeof(WCHAR); 

    // проверить корректность имени файла
    if (cbFileName >= 1024 * sizeof(WCHAR)) Exception::Throw(E_INVALIDARG); 

    // выделить буфер требуемого размера
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 2048 * sizeof(WCHAR)] = {0}; 

    // выполнить преобразование типа
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // указать размер структуры
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // указать смещение имени сеанса и лог-файла
    pProperties->LoggerNameOffset  = sizeof(EVENT_TRACE_PROPERTIES); 
    pProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR); 

    // получить свойства сеанса трассировки
    ULONG code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // указать тип структуры
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; 

    // при наличии имени файла
    if (pProperties->LogFileNameOffset != 0)
    {
        // выполнить преобразование типа
        PWSTR szCurrentFileName = (PWSTR)((PBYTE)pProperties + pProperties->LogFileNameOffset); 

        // проверить изменение параметра
        if (::lstrcmpiW(szCurrentFileName, szFileName) == 0) return; 

        // скопировать имя файла
        memcpy(szCurrentFileName, szFileName, cbFileName); 
    }
    else {
        // указать смещение имени сеанса и лог-файла
        pProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR); 

        // выполнить преобразование типа
        PWSTR szCurrentFileName = (PWSTR)((PBYTE)pProperties + pProperties->LogFileNameOffset); 

        // скопировать имя файла
        memcpy(szCurrentFileName, szFileName, cbFileName); 
    }
    // изменить параметры сеанса трассировки
    code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_UPDATE); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 
}

void ETW::ConsumerLogger::Flush()
{
    // выделить буфер требуемого размера
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 2048 * sizeof(WCHAR)] = {0}; 

    // выполнить преобразование типа
    PEVENT_TRACE_PROPERTIES pProperties = (PEVENT_TRACE_PROPERTIES)buffer; 

    // указать размер структуры
    pProperties->Wnode.BufferSize = sizeof(buffer); 

    // указать смещение имени сеанса и лог-файла
    pProperties->LoggerNameOffset  = sizeof(EVENT_TRACE_PROPERTIES); 
    pProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(WCHAR); 

    // получить свойства сеанса трассировки
    ULONG code = ::ControlTraceW(Handle(), nullptr, pProperties, EVENT_TRACE_CONTROL_QUERY); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 

    // указать тип структуры
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; 

    // скопировать имя сеанса
    memcpy(pProperties + 1, Name(), (wcslen(Name()) + 1) * sizeof(WCHAR)); 

    // сбросить буферы в лог-файл или потребителям
    code = ::ControlTraceW(Handle(), Name(), pProperties, EVENT_TRACE_CONTROL_FLUSH); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) Exception::Throw(HRESULT_FROM_WIN32(code)); 
}
