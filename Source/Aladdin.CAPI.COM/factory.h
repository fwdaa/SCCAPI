#pragma once

///////////////////////////////////////////////////////////////////////////////
// Описание регистрируемых компонентов
///////////////////////////////////////////////////////////////////////////////
struct COM_DESC { PCWSTR szProgID; PCWSTR szRuntime; }; 

///////////////////////////////////////////////////////////////////////////////
// Регистрация COM-компонентов
///////////////////////////////////////////////////////////////////////////////

// зарегистрировать COM-компонент
void RegisterComObject(HMODULE hModule, 
    PCWSTR szCLSID, PCWSTR szProgID, PCWSTR szThreading
); 
// отменить регистрацию COM-компонента
void UnregisterComObject(PCWSTR szCLSID); 

///////////////////////////////////////////////////////////////////////////////
// Фабрика компонента
///////////////////////////////////////////////////////////////////////////////
class _ClassFactoryNET
{
	// фабрика класса и счетчик блокировок модуля
	private: IClassFactory* pFactory; volatile LONG* pLocks; 

    // конструктор/деструктор
    public: _ClassFactoryNET(volatile LONG* pLocks)
    {
	    // инициализировать переменные
	    pFactory = 0; this->pLocks = pLocks; LockServer(TRUE);
    }
    public: virtual ~_ClassFactoryNET()
    {
	    // освободить выделенные ресурсы
	    if (pFactory) pFactory->Release(); LockServer(FALSE); 
    }
	///////////////////////////////////////////////////////////////////////////
	// Реализация интерфейса IClassFactory
	///////////////////////////////////////////////////////////////////////////

    // создать объект
    public: HRESULT CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject); 

    // изменить счетчик ссылок сервера
    public: HRESULT LockServer(BOOL fLock) 
    {
        // увеличить число блокировок
        if (fLock) ::InterlockedIncrement(pLocks); 

        // уменьшить число блокировок
        else ::InterlockedDecrement(pLocks); return S_OK; 
    }
	///////////////////////////////////////////////////////////////////////////
    // Абстрактные функции
	///////////////////////////////////////////////////////////////////////////

    // идентификатор интерфейса
	protected: virtual REFIID GetIID() const = 0; 
	// таблица регистрации компонентов
    protected: virtual CONST COM_DESC* Components() const = 0; 

	///////////////////////////////////////////////////////////////////////////
    // Вспомогательные методы
	///////////////////////////////////////////////////////////////////////////

    // найти фабрику компонента
    protected: CONST COM_DESC* FindComponent(); 
    // найти фабрику компонента
    protected: CONST COM_DESC* FindComponent(PCWSTR szRuntime); 
};

template <class Interface>
class ClassFactoryNET : public Interface, protected _ClassFactoryNET
{
    // компонент выбранной среды выполнения и счетчик ссылок
    private: CONST COM_DESC* pComponent; ULONG cRef; 

    // конструктор/деструктор
    public: ClassFactoryNET(volatile LONG* pLocks) 
        
        // сохранить переданные параметры
        : _ClassFactoryNET(pLocks), pComponent(0), cRef(1) {}

    // идентификатор интерфейса
	protected: virtual REFIID GetIID() const override { return __uuidof(Interface); }

	///////////////////////////////////////////////////////////////////////////
	// Реализация интерфейса IUnknown
	///////////////////////////////////////////////////////////////////////////

    // запросить интерфейс
    public: virtual HRESULT STDMETHODCALLTYPE QueryInterface(
        REFIID riid, void** ppvObject) override
    {
        // проверить корректность данных
        if (ppvObject == 0) return E_POINTER; *ppvObject = 0; 

        // указать идентификатор интерфейса
        REFIID iidFactory = __uuidof(Interface); 

        // при поддержке интерфейса
        if (InlineIsEqualGUID(riid, iidFactory       ) || 
            InlineIsEqualGUID(riid, IID_IClassFactory) || 
            InlineIsEqualGUID(riid, IID_IUnknown     ))
        {
            // вернуть указать на объект
            *ppvObject = this; AddRef(); return S_OK; 
        }
        return E_NOINTERFACE; 
    }
    // увеличить счетчик ссылок
    public: virtual ULONG STDMETHODCALLTYPE AddRef() override { return ++cRef; }

    // уменьшить счетчик ссылок
    public: virtual ULONG STDMETHODCALLTYPE Release() override
    {
        // уменьшить счетчик ссылок
        if (--cRef != 0) return cRef; delete this; return 0; 
    }
	///////////////////////////////////////////////////////////////////////////
	// Реализация интерфейса IClassFactory
	///////////////////////////////////////////////////////////////////////////

    // создать объект
    public: virtual HRESULT STDMETHODCALLTYPE CreateInstance( 
        IUnknown* pUnkOuter, REFIID riid, void** ppvObject) override
    {
        // найти соответствующий компонент
        if (pComponent == 0) pComponent = FindComponent(); 
	    
        // проверить наличие компонента
        if (pComponent == 0) return CLASS_E_CLASSNOTAVAILABLE; 

        // создать объект   
        return _ClassFactoryNET::CreateInstance(pUnkOuter, riid, ppvObject); 
    }
    // изменить счетчик ссылок сервера
    public: virtual HRESULT STDMETHODCALLTYPE LockServer(BOOL fLock) override
    {
        // изменить счетчик ссылок сервера
        return _ClassFactoryNET::LockServer(fLock); 
    }
	///////////////////////////////////////////////////////////////////////////
	// Реализация COM-интерфейса
	///////////////////////////////////////////////////////////////////////////

    // установить среду выполнения
    public: virtual HRESULT STDMETHODCALLTYPE put_Runtime(BSTR version) override
    {
        // найти соответствующий компонент
        CONST COM_DESC* pFindComponent = FindComponent(version); 

        // проверить наличие компонента
        if (!pFindComponent) return CLASS_E_CLASSNOTAVAILABLE;

        // сохранить найденный компонент
        pComponent = pFindComponent; return S_OK; 
    }
    // получить среду выполнения
    public: virtual HRESULT STDMETHODCALLTYPE get_Runtime(BSTR* version) override
    {
	    // проверить корректность параметров
        if (version == 0) return E_POINTER; 
	    
        // найти соответствующий компонент
        if (pComponent == 0) pComponent = FindComponent(); 
	    
        // проверить наличие компонента
        if (pComponent == 0) return CLASS_E_CLASSNOTAVAILABLE; 

	    // вернуть версию среды
        *version = ::SysAllocString(pComponent->szRuntime); return S_OK; 
    }
};
