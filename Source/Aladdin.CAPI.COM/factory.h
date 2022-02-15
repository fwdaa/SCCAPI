#pragma once

///////////////////////////////////////////////////////////////////////////////
// �������� �������������� �����������
///////////////////////////////////////////////////////////////////////////////
struct COM_DESC { PCWSTR szProgID; PCWSTR szRuntime; }; 

///////////////////////////////////////////////////////////////////////////////
// ����������� COM-�����������
///////////////////////////////////////////////////////////////////////////////

// ���������������� COM-���������
void RegisterComObject(HMODULE hModule, 
    PCWSTR szCLSID, PCWSTR szProgID, PCWSTR szThreading
); 
// �������� ����������� COM-����������
void UnregisterComObject(PCWSTR szCLSID); 

///////////////////////////////////////////////////////////////////////////////
// ������� ����������
///////////////////////////////////////////////////////////////////////////////
class _ClassFactoryNET
{
	// ������� ������ � ������� ���������� ������
	private: IClassFactory* pFactory; volatile LONG* pLocks; 

    // �����������/����������
    public: _ClassFactoryNET(volatile LONG* pLocks)
    {
	    // ���������������� ����������
	    pFactory = 0; this->pLocks = pLocks; LockServer(TRUE);
    }
    public: virtual ~_ClassFactoryNET()
    {
	    // ���������� ���������� �������
	    if (pFactory) pFactory->Release(); LockServer(FALSE); 
    }
	///////////////////////////////////////////////////////////////////////////
	// ���������� ���������� IClassFactory
	///////////////////////////////////////////////////////////////////////////

    // ������� ������
    public: HRESULT CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject); 

    // �������� ������� ������ �������
    public: HRESULT LockServer(BOOL fLock) 
    {
        // ��������� ����� ����������
        if (fLock) ::InterlockedIncrement(pLocks); 

        // ��������� ����� ����������
        else ::InterlockedDecrement(pLocks); return S_OK; 
    }
	///////////////////////////////////////////////////////////////////////////
    // ����������� �������
	///////////////////////////////////////////////////////////////////////////

    // ������������� ����������
	protected: virtual REFIID GetIID() const = 0; 
	// ������� ����������� �����������
    protected: virtual CONST COM_DESC* Components() const = 0; 

	///////////////////////////////////////////////////////////////////////////
    // ��������������� ������
	///////////////////////////////////////////////////////////////////////////

    // ����� ������� ����������
    protected: CONST COM_DESC* FindComponent(); 
    // ����� ������� ����������
    protected: CONST COM_DESC* FindComponent(PCWSTR szRuntime); 
};

template <class Interface>
class ClassFactoryNET : public Interface, protected _ClassFactoryNET
{
    // ��������� ��������� ����� ���������� � ������� ������
    private: CONST COM_DESC* pComponent; ULONG cRef; 

    // �����������/����������
    public: ClassFactoryNET(volatile LONG* pLocks) 
        
        // ��������� ���������� ���������
        : _ClassFactoryNET(pLocks), pComponent(0), cRef(1) {}

    // ������������� ����������
	protected: virtual REFIID GetIID() const override { return __uuidof(Interface); }

	///////////////////////////////////////////////////////////////////////////
	// ���������� ���������� IUnknown
	///////////////////////////////////////////////////////////////////////////

    // ��������� ���������
    public: virtual HRESULT STDMETHODCALLTYPE QueryInterface(
        REFIID riid, void** ppvObject) override
    {
        // ��������� ������������ ������
        if (ppvObject == 0) return E_POINTER; *ppvObject = 0; 

        // ������� ������������� ����������
        REFIID iidFactory = __uuidof(Interface); 

        // ��� ��������� ����������
        if (InlineIsEqualGUID(riid, iidFactory       ) || 
            InlineIsEqualGUID(riid, IID_IClassFactory) || 
            InlineIsEqualGUID(riid, IID_IUnknown     ))
        {
            // ������� ������� �� ������
            *ppvObject = this; AddRef(); return S_OK; 
        }
        return E_NOINTERFACE; 
    }
    // ��������� ������� ������
    public: virtual ULONG STDMETHODCALLTYPE AddRef() override { return ++cRef; }

    // ��������� ������� ������
    public: virtual ULONG STDMETHODCALLTYPE Release() override
    {
        // ��������� ������� ������
        if (--cRef != 0) return cRef; delete this; return 0; 
    }
	///////////////////////////////////////////////////////////////////////////
	// ���������� ���������� IClassFactory
	///////////////////////////////////////////////////////////////////////////

    // ������� ������
    public: virtual HRESULT STDMETHODCALLTYPE CreateInstance( 
        IUnknown* pUnkOuter, REFIID riid, void** ppvObject) override
    {
        // ����� ��������������� ���������
        if (pComponent == 0) pComponent = FindComponent(); 
	    
        // ��������� ������� ����������
        if (pComponent == 0) return CLASS_E_CLASSNOTAVAILABLE; 

        // ������� ������   
        return _ClassFactoryNET::CreateInstance(pUnkOuter, riid, ppvObject); 
    }
    // �������� ������� ������ �������
    public: virtual HRESULT STDMETHODCALLTYPE LockServer(BOOL fLock) override
    {
        // �������� ������� ������ �������
        return _ClassFactoryNET::LockServer(fLock); 
    }
	///////////////////////////////////////////////////////////////////////////
	// ���������� COM-����������
	///////////////////////////////////////////////////////////////////////////

    // ���������� ����� ����������
    public: virtual HRESULT STDMETHODCALLTYPE put_Runtime(BSTR version) override
    {
        // ����� ��������������� ���������
        CONST COM_DESC* pFindComponent = FindComponent(version); 

        // ��������� ������� ����������
        if (!pFindComponent) return CLASS_E_CLASSNOTAVAILABLE;

        // ��������� ��������� ���������
        pComponent = pFindComponent; return S_OK; 
    }
    // �������� ����� ����������
    public: virtual HRESULT STDMETHODCALLTYPE get_Runtime(BSTR* version) override
    {
	    // ��������� ������������ ����������
        if (version == 0) return E_POINTER; 
	    
        // ����� ��������������� ���������
        if (pComponent == 0) pComponent = FindComponent(); 
	    
        // ��������� ������� ����������
        if (pComponent == 0) return CLASS_E_CLASSNOTAVAILABLE; 

	    // ������� ������ �����
        *version = ::SysAllocString(pComponent->szRuntime); return S_OK; 
    }
};
