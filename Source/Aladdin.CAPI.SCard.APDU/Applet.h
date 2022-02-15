#pragma once
#undef CreateFile
#undef T1

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU
{
///////////////////////////////////////////////////////////////////////////
// ���������� ���������� LibAPDU
///////////////////////////////////////////////////////////////////////////
[Serializable]
public ref class LibException : Aladdin::PCSC::Exception
{	
    // �����������
    public: LibException(int code) : Aladdin::PCSC::Exception(code) {}
};

///////////////////////////////////////////////////////////////////////////
// ������ �� ������ LibAPDU
///////////////////////////////////////////////////////////////////////////
public ref class LibApplet abstract : Applet
{	
    // ����� �������������� �� �����-������
	private: PCSC::ReaderSession^ session; 

    // ���������� ����������� LibAPDU
	private: libapdu::ISender* sender; private: libapdu::IToken* token; 

    // ���������� ������������� � ������� �������������
	private: int id; private: bool initialized;  

    // �����������
    protected: LibApplet(SCard::Card^ store, String^ name, int id, 
		PCSC::ReaderSession^ session, array<BYTE>^ atr
	);  
    // ����������
    public: virtual ~LibApplet();  
    // ����������
    protected: !LibApplet() { delete token; delete sender; }

    // ����� �������������� � ��������
    public: virtual property PCSC::ReaderSession^ Session
    { 
        // ����� �������������� � ��������
        PCSC::ReaderSession^ get() override { return session; }
    }
    // ����� �������������� �� �����-������
	public: libapdu::IToken* Token() { return token; } 

    // ����� ������� �� ������
    protected: void Select();  

    ///////////////////////////////////////////////////////////////////////
    // ����� ���������� 
    ///////////////////////////////////////////////////////////////////////

    // ��������� ������ � ����� ����� ������
	public: virtual UInt32 FreeMemory () override; 
	public: virtual UInt32 TotalMemory() override;

    // �������� ����� �����-�����
	public: virtual String^ GetLabel() override;  
    // ���������� ����� �����-�����
	public: virtual void SetLabel(String^ value) override;  

    // ������ �������
	public: virtual String^ GetHardwareVersion() override;  
	public: virtual String^ GetSoftwareVersion() override;  
			
    // �������������� �������
	public: virtual array<BYTE>^ GetHardwareID() override;  
	public: virtual array<BYTE>^ GetSoftwareID() override;  

    ///////////////////////////////////////////////////////////////////////
    // �������� ������� (AppletSelectLevel::Maximal)
    ///////////////////////////////////////////////////////////////////////

    // ������� ������ �������� �������
    public: virtual IAppletFileFolder^ OpenFolder(... array<WORD>^ path) override; 
    public: virtual IAppletFile^       OpenFile  (... array<WORD>^ path) override;

    // ������� ������ �������� �������
	public: virtual void RemoveFolder(... array<WORD>^ path) override; 
    public: virtual void RemoveFile  (... array<WORD>^ path) override;

    ///////////////////////////////////////////////////////////////////////
    // �������������� �������
    ///////////////////////////////////////////////////////////////////////

    // �������������� ���� ��������������
	public: virtual array<Type^>^ GetAuthenticationTypes(String^ user) override; 

	// �������� �������� ��������������
	public: virtual AuthenticationService^ GetAuthenticationService(
		String^ user, Type^ authenticationType) override; 

	// ��������� ������������� ��������������
	public: virtual bool IsAuthenticationRequired(Exception^ e) override; 

	// �������� ��������������
	public: virtual bool Logout(); 

	// ������� ������� �������������� ��������������
	protected: virtual int HasAdminAuthentication() { return 0; } 
};
///////////////////////////////////////////////////////////////////////////
// ������ �������� �������
///////////////////////////////////////////////////////////////////////////
[SecurityObject("applet")]
public ref class LibAppletFileObject : MarshalByRefObject, IAppletFileObject
{
	// ������ � ���� � �����
	private: LibApplet^ applet; array<WORD>^ path; 

	// �����������
	public: LibAppletFileObject(LibApplet^ applet, array<WORD>^ path)
	
		// ��������� ���������� ���������
		{ this->applet = applet; this->path = path; }  

    // ������������ ������ 
	public: property LibApplet^ Applet 
    { 
        // ������ �������
        LibApplet^ get() { return applet; }
    }
    // ������� ������ �������� �������
	public: void Select(); 

    // ���� � ������� �������� ������� 
    public: virtual property array<WORD>^ Path 
    { 
        // ���� � ������� �������� ������� 
        array<WORD>^ get() { return path; }
    }
    // �������� ���������� ������� �������� �������
	public: virtual FileObjectInfo GetInfo(); 
}; 
///////////////////////////////////////////////////////////////////////////
// ���� �� �����-�����
///////////////////////////////////////////////////////////////////////////
public ref class LibAppletFile : LibAppletFileObject, IAppletFile
{
	// �����������
	public: LibAppletFile(LibApplet^ applet, array<WORD>^ path); 
    // ����������
    public: virtual ~LibAppletFile();  

    // ��������� ������ ���������� �����
	public: virtual void Read(array<BYTE>^ data, int offset); 
    // �������� ������ � ��������� ����
	public: virtual void Write(array<BYTE>^ data, int offset); 
}; 
///////////////////////////////////////////////////////////////////////////
// ������� �� �����-����� 
///////////////////////////////////////////////////////////////////////////
public ref class LibAppletFileFolder : LibAppletFileObject, IAppletFileFolder
{
	// �����������
	public: LibAppletFileFolder(LibApplet^ applet, array<WORD>^ path); 
    // ����������
    public: virtual ~LibAppletFileFolder();  

    // ������� ������ �������� �������� �������
	public: virtual array<WORD>^ EnumerateFolders(); 
	public: virtual array<WORD>^ EnumerateFiles  (); 

    // ������� ������ �������� �������
	public: virtual IAppletFileFolder^ CreateFolder(WORD name, FileObjectInfo info); 
	public: virtual IAppletFile^       CreateFile  (WORD name, FileObjectInfo info); 

    // ������� ������ �������� �������
	public: virtual IAppletFileFolder^ OpenFolder(WORD name); 
	public: virtual IAppletFile^       OpenFile  (WORD name); 

    // ������� ��������� ������ �������� �������
	public: virtual void RemoveFolder(WORD name); 
	public: virtual void RemoveFile  (WORD name); 
}; 
}}}}