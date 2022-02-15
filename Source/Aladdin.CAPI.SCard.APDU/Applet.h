#pragma once
#undef CreateFile
#undef T1

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU
{
///////////////////////////////////////////////////////////////////////////
// Исключение библиотеки LibAPDU
///////////////////////////////////////////////////////////////////////////
[Serializable]
public ref class LibException : Aladdin::PCSC::Exception
{	
    // конструктор
    public: LibException(int code) : Aladdin::PCSC::Exception(code) {}
};

///////////////////////////////////////////////////////////////////////////
// Апплет на основе LibAPDU
///////////////////////////////////////////////////////////////////////////
public ref class LibApplet abstract : Applet
{	
    // сеанс взаимодействия со смарт-картой
	private: PCSC::ReaderSession^ session; 

    // реализация интерфейсов LibAPDU
	private: libapdu::ISender* sender; private: libapdu::IToken* token; 

    // внутренний идентификатор и признак инициализации
	private: int id; private: bool initialized;  

    // конструктор
    protected: LibApplet(SCard::Card^ store, String^ name, int id, 
		PCSC::ReaderSession^ session, array<BYTE>^ atr
	);  
    // деструктор
    public: virtual ~LibApplet();  
    // деструктор
    protected: !LibApplet() { delete token; delete sender; }

    // сеанс взаимодействия с апплетом
    public: virtual property PCSC::ReaderSession^ Session
    { 
        // сеанс взаимодействия с апплетом
        PCSC::ReaderSession^ get() override { return session; }
    }
    // сеанс взаимодействия со смарт-картой
	public: libapdu::IToken* Token() { return token; } 

    // выбор апплета на токене
    protected: void Select();  

    ///////////////////////////////////////////////////////////////////////
    // Общая информация 
    ///////////////////////////////////////////////////////////////////////

    // свободная память и общий объем памяти
	public: virtual UInt32 FreeMemory () override; 
	public: virtual UInt32 TotalMemory() override;

    // получить метку смарт-карты
	public: virtual String^ GetLabel() override;  
    // установить метку смарт-карты
	public: virtual void SetLabel(String^ value) override;  

    // версии апплета
	public: virtual String^ GetHardwareVersion() override;  
	public: virtual String^ GetSoftwareVersion() override;  
			
    // идентификаторы апплета
	public: virtual array<BYTE>^ GetHardwareID() override;  
	public: virtual array<BYTE>^ GetSoftwareID() override;  

    ///////////////////////////////////////////////////////////////////////
    // Файловая система (AppletSelectLevel::Maximal)
    ///////////////////////////////////////////////////////////////////////

    // открыть объект файловой системы
    public: virtual IAppletFileFolder^ OpenFolder(... array<WORD>^ path) override; 
    public: virtual IAppletFile^       OpenFile  (... array<WORD>^ path) override;

    // удалить объект файловой системы
	public: virtual void RemoveFolder(... array<WORD>^ path) override; 
    public: virtual void RemoveFile  (... array<WORD>^ path) override;

    ///////////////////////////////////////////////////////////////////////
    // Аутентификация апплета
    ///////////////////////////////////////////////////////////////////////

    // поддерживаемые типы аутентификации
	public: virtual array<Type^>^ GetAuthenticationTypes(String^ user) override; 

	// получить протокол аутентификации
	public: virtual AuthenticationService^ GetAuthenticationService(
		String^ user, Type^ authenticationType) override; 

	// проверить необходимость аутентификации
	public: virtual bool IsAuthenticationRequired(Exception^ e) override; 

	// сбросить аутентификацию
	public: virtual bool Logout(); 

	// признак наличия аутентификации администратора
	protected: virtual int HasAdminAuthentication() { return 0; } 
};
///////////////////////////////////////////////////////////////////////////
// Объект файловой системы
///////////////////////////////////////////////////////////////////////////
[SecurityObject("applet")]
public ref class LibAppletFileObject : MarshalByRefObject, IAppletFileObject
{
	// апплет и путь к файлу
	private: LibApplet^ applet; array<WORD>^ path; 

	// конструктор
	public: LibAppletFileObject(LibApplet^ applet, array<WORD>^ path)
	
		// сохранить переданные параметры
		{ this->applet = applet; this->path = path; }  

    // используемый апплет 
	public: property LibApplet^ Applet 
    { 
        // апплет сервиса
        LibApplet^ get() { return applet; }
    }
    // выбрать объект файловой системы
	public: void Select(); 

    // путь к объекту файловой системы 
    public: virtual property array<WORD>^ Path 
    { 
        // путь к объекту файловой системы 
        array<WORD>^ get() { return path; }
    }
    // получить информацию объекта файловой системы
	public: virtual FileObjectInfo GetInfo(); 
}; 
///////////////////////////////////////////////////////////////////////////
// Файл на смарт-карте
///////////////////////////////////////////////////////////////////////////
public ref class LibAppletFile : LibAppletFileObject, IAppletFile
{
	// конструктор
	public: LibAppletFile(LibApplet^ applet, array<WORD>^ path); 
    // деструктор
    public: virtual ~LibAppletFile();  

    // прочитать данные выбранного файла
	public: virtual void Read(array<BYTE>^ data, int offset); 
    // записать данные в выбранный файл
	public: virtual void Write(array<BYTE>^ data, int offset); 
}; 
///////////////////////////////////////////////////////////////////////////
// Каталог на смарт-карте 
///////////////////////////////////////////////////////////////////////////
public ref class LibAppletFileFolder : LibAppletFileObject, IAppletFileFolder
{
	// конструктор
	public: LibAppletFileFolder(LibApplet^ applet, array<WORD>^ path); 
    // деструктор
    public: virtual ~LibAppletFileFolder();  

    // вернуть список объектов файловой системы
	public: virtual array<WORD>^ EnumerateFolders(); 
	public: virtual array<WORD>^ EnumerateFiles  (); 

    // создать объект файловой системы
	public: virtual IAppletFileFolder^ CreateFolder(WORD name, FileObjectInfo info); 
	public: virtual IAppletFile^       CreateFile  (WORD name, FileObjectInfo info); 

    // открыть объект файловой системы
	public: virtual IAppletFileFolder^ OpenFolder(WORD name); 
	public: virtual IAppletFile^       OpenFile  (WORD name); 

    // удалить выбранный объект файловой системы
	public: virtual void RemoveFolder(WORD name); 
	public: virtual void RemoveFile  (WORD name); 
}; 
}}}}