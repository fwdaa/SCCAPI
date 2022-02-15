#include "StdAfx.h"
#include "Applet.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "AppletFile.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Объект файловой системы
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::SCard::APDU::LibAppletFileObject::Select()
{$
    // получить интерфейс LibAPDU
    libapdu::IAppFS& fs = Applet->Token()->fs(); 
	try {
        // выделить память для пути объекта
		libapdu::TPath objectPath(path->Length, 0); 

        // скопировать все компоненты пути
		for (int i = 0; i < path->Length; i++) objectPath[i] = path[i];

        // выбрать объект файловой системы
		fs.select(objectPath);
    }
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

Aladdin::CAPI::SCard::FileObjectInfo 
Aladdin::CAPI::SCard::APDU::LibAppletFileObject::GetInfo()
{$
    // получить интерфейс LibAPDU
    libapdu::IToken* token = Applet->Token(); Select(); 
	try	{
        // получить информацию объекта файловой системы
		libapdu::CFileInfo fi(token->fs().info()); 

        // получить тип доступа к объекту файловой системы
		libapdu::TFileAccess userAccess = (libapdu::TFileAccess)token->pin().pathUser().back();

        // указать начальные условия
        array<String^>^ readAccessUsers = nullptr; array<String^>^ writeAccessUsers = nullptr;

        // указать тип доступа к объекту
        if (fi.read  == userAccess) readAccessUsers  = gcnew array<String^> { "USER" }; 
        if (fi.write == userAccess) writeAccessUsers = gcnew array<String^> { "USER" }; 

        // вернуть собранную информацию
		return FileObjectInfo(fi.size, readAccessUsers, writeAccessUsers); 
    }
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

///////////////////////////////////////////////////////////////////////////
// Файл на смарт-карте
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::SCard::APDU::LibAppletFile::LibAppletFile(
	LibApplet^ applet, array<WORD>^ path) : LibAppletFileObject(applet, path) 
{$
    // получить интерфейс LibAPDU
    libapdu::IAppFS& fs = Applet->Token()->fs(); 
    try { 
        // выделить память для пути объекта
        libapdu::TPath objectPath(path->Length, 0); 

        // скопировать все компоненты пути
		for (int i = 0; i < path->Length; i++) objectPath[i] = path[i];

        // выбрать объект файловой системы
	    fs.select(objectPath); libapdu::CFileInfo fi(fs.info());

        // проверить корректность типа
        if (fi.type != libapdu::TTypeFile) throw gcnew ArgumentException(); 
    }
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
} 

Aladdin::CAPI::SCard::APDU::LibAppletFile::~LibAppletFile() { $ } 

		
void Aladdin::CAPI::SCard::APDU::LibAppletFile::Read(array<BYTE>^ data, int offset)
{$
    // получить интерфейс LibAPDU
    libapdu::IAppFS& fs = Applet->Token()->fs(); Select(); 
	try {
		// выделить буфер требуемого размера
		libapdu::TBytes buffer(data->Length, 0); 

        // прочитать данные из файла в буфер
		fs.read(buffer, offset);

        // скопировать данные в переданный буфер
		Marshal::Copy(IntPtr(&buffer[0]), data, 0, data->Length); 
	}
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

void Aladdin::CAPI::SCard::APDU::LibAppletFile::Write(array<BYTE>^ data, int offset)
{$
    // получить интерфейс LibAPDU
    libapdu::IAppFS& fs = Applet->Token()->fs(); Select(); 
	try {
		// выделить буфер требуемого размера
		libapdu::TBytes buffer(data->Length, 0); 

        // скопировать данные в созданный буфер
		Marshal::Copy(data, 0, IntPtr(&buffer[0]), data->Length);

        // записать данные из буфера в файл
		fs.write(buffer, offset); 
	}
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

///////////////////////////////////////////////////////////////////////////
// Каталог на смарт-карте 
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::SCard::APDU::LibAppletFileFolder::LibAppletFileFolder(
	LibApplet^ applet, array<WORD>^ path) : LibAppletFileObject(applet, path) 
{$
    // получить интерфейс LibAPDU
    libapdu::IAppFS& fs = Applet->Token()->fs(); 
    try { 
        // выделить память для пути объекта
        libapdu::TPath objectPath(path->Length, 0); 

        // скопировать все компоненты пути
		for (int i = 0; i < path->Length; i++) objectPath[i] = path[i];

        // выбрать объект файловой системы
	    fs.select(objectPath); libapdu::CFileInfo fi(fs.info());

        // проверить корректность типа
        if (fi.type != libapdu::TTypeDir) throw gcnew ArgumentException(); 
    }
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
} 

Aladdin::CAPI::SCard::APDU::LibAppletFileFolder::~LibAppletFileFolder() { $ } 

		
array<WORD>^ Aladdin::CAPI::SCard::APDU::LibAppletFileFolder::EnumerateFolders()
{$
    // получить интерфейс LibAPDU
    libapdu::IAppFS& fs = Applet->Token()->fs(); Select(); 
	try {
        // перечислить объекты файловой системы			
        libapdu::TList fileList = fs.list(libapdu::TTypeDir);
		
        // создать список идентифмикаторов	
		array<WORD>^ retValue = gcnew array<WORD>((int)fileList.size());
				
        // заполнить список идентификаторов
        for (int i = 0; i < retValue->Length; i++) retValue[i] = fileList[i]; return retValue;
    }
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

array<WORD>^ Aladdin::CAPI::SCard::APDU::LibAppletFileFolder::EnumerateFiles()
{$
    // получить интерфейс LibAPDU
    libapdu::IAppFS& fs = Applet->Token()->fs(); Select(); 
	try {
        // перечислить объекты файловой системы			
        libapdu::TList fileList = fs.list(libapdu::TTypeFile);
		
        // создать список идентифмикаторов	
		array<WORD>^ retValue = gcnew array<WORD>((int)fileList.size());
				
        // заполнить список идентификаторов
        for (int i = 0; i < retValue->Length; i++) retValue[i] = fileList[i]; return retValue;
    }
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

Aladdin::CAPI::SCard::IAppletFileFolder^ 
Aladdin::CAPI::SCard::APDU::LibAppletFileFolder::CreateFolder(WORD name, FileObjectInfo info)
{$
    // проверить корректность имени объекта файловой системы
	if (name == 0x0000 || name == 0xFFFF || name == 0x3FFF || name == 0x3F00) 
    {
        // при ошибке выбросить исключение
        throw gcnew ArgumentException(nullptr);
    }
    // получить интерфейс LibAPDU
    libapdu::IAppFS& fs = Applet->Token()->fs();  
	try {
        // указать тип объекта файловой системы
	    libapdu::CFileInfo fi; fi.type = libapdu::TTypeDir; 

        // указать тип доступа к объекту файловой системы
        fi.read  = libapdu::TAccessEveryone; 
		fi.write = libapdu::TAccessEveryone; 

		// создать объект файловой системы
        Select(); fi.size = 0; fs.create(name, fi); 

        // выделить память для пути объекта
        array<WORD>^ path = gcnew array<WORD>(Path->Length + 1); 

        // создать путь для объекта
        Array::Copy(Path, 0, path, 0, Path->Length); path[Path->Length] = name; 

        // вернуть созданный объект
        return gcnew LibAppletFileFolder(Applet, path);
    }
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

Aladdin::CAPI::SCard::IAppletFile^ 
Aladdin::CAPI::SCard::APDU::LibAppletFileFolder::CreateFile(WORD name, FileObjectInfo info)
{$
    // проверить корректность имени объекта файловой системы
	if (name == 0x0000 || name == 0xFFFF || name == 0x3FFF || name == 0x3F00) 
    {
        // при ошибке выбросить исключение
        throw gcnew ArgumentException(nullptr);
    }
    // получить интерфейс LibAPDU
    libapdu::IAppFS& fs = Applet->Token()->fs(); libapdu::IAppPin& pin = Applet->Token()->pin();
	try {
        // указать тип объекта файловой системы
		libapdu::CFileInfo fi; fi.type = libapdu::TTypeFile; 

        // указать тип доступа к объекту файловой системы
        fi.read = libapdu::TAccessEveryone; fi.write = libapdu::TAccessEveryone; 

        // проверить наличие пользовательского доступе к файлу
        Nullable<bool> readAccess  = info.HasReadAccess ("USER"); 
        Nullable<bool> writeAccess = info.HasWriteAccess("USER");

        // при пользовательском доступе к файлу
	    if ((readAccess .HasValue && readAccess .Value) || 
            (writeAccess.HasValue && writeAccess.Value))
		{
			// получить тип доступа к объекту файловой системы
			libapdu::TFileAccess userAccess = (libapdu::TFileAccess)pin.pathUser().back();

			// указать признак пользовательского доступа
			if (readAccess .HasValue && readAccess .Value) fi.read  = userAccess;
			if (writeAccess.HasValue && writeAccess.Value) fi.write = userAccess; 
        } 
        // создать объект файловой системы
        Select(); fi.size = libapdu::TFileSize(info.ObjectSize); fs.create(name, fi);

        // выделить память для пути объекта
        array<WORD>^ path = gcnew array<WORD>(Path->Length + 1); 

        // создать путь для объекта
        Array::Copy(Path, 0, path, 0, Path->Length); path[Path->Length] = name; 

        // вернуть созданный объект
        return gcnew LibAppletFile(Applet, path); 
    }
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

Aladdin::CAPI::SCard::IAppletFileFolder^ 
Aladdin::CAPI::SCard::APDU::LibAppletFileFolder::OpenFolder(WORD name)
{$
    // выделить память для пути объекта
    array<WORD>^ path = gcnew array<WORD>(Path->Length + 1); 

    // создать путь для объекта
    Array::Copy(Path, 0, path, 0, Path->Length); path[Path->Length] = name; 

    // вернуть отрытый объект файловой системы
    return gcnew LibAppletFileFolder(Applet, path); 
}

Aladdin::CAPI::SCard::IAppletFile^ 
Aladdin::CAPI::SCard::APDU::LibAppletFileFolder::OpenFile(WORD name)
{$
    // выделить память для пути объекта
    array<WORD>^ path = gcnew array<WORD>(Path->Length + 1); 

    // создать путь для объекта
    Array::Copy(Path, 0, path, 0, Path->Length); path[Path->Length] = name; 

    // вернуть отрытый объект файловой системы
    return gcnew LibAppletFile(Applet, path); 
}

void Aladdin::CAPI::SCard::APDU::LibAppletFileFolder::RemoveFolder(WORD name)
{$
    // выделить память для пути объекта
    array<WORD>^ path = gcnew array<WORD>(Path->Length + 1); 

    // создать путь для объекта
    Array::Copy(Path, 0, path, 0, Path->Length); path[Path->Length] = name; 

    // получить интерфейс LibAPDU
    libapdu::IAppFS& fs = Applet->Token()->fs(); 
	try {
		// выбрать и удалить объект каталога
		LibAppletFileFolder(Applet, path); fs.remove();
	}
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

void Aladdin::CAPI::SCard::APDU::LibAppletFileFolder::RemoveFile(WORD name)
{$
    // выделить память для пути объекта
    array<WORD>^ path = gcnew array<WORD>(Path->Length + 1); 

    // создать путь для объекта
    Array::Copy(Path, 0, path, 0, Path->Length); path[Path->Length] = name; 

    // получить интерфейс LibAPDU
    libapdu::IAppFS& fs = Applet->Token()->fs(); 
	try {	
		// выбрать и удалить объект файла
		LibAppletFile(Applet, path); fs.remove();
    }
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

///////////////////////////////////////////////////////////////////////
// Файловая система апплета
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::SCard::IAppletFileFolder^ 
Aladdin::CAPI::SCard::APDU::LibApplet::OpenFolder(... array<WORD>^ path)
{$
	try { 
        // выбрать апплет требуемым способом
		if (!initialized) Token()->selectApplet(id); 

		// вернуть отрытый объект файловой системы
		return gcnew LibAppletFileFolder(this, path); 
	}
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

Aladdin::CAPI::SCard::IAppletFile^ 
Aladdin::CAPI::SCard::APDU::LibApplet::OpenFile(... array<WORD>^ path)
{$
	try {
        // выбрать апплет требуемым способом
		if (!initialized) Token()->selectApplet(id); 

		// вернуть отрытый объект файловой системы
		return gcnew LibAppletFile(this, path); 
	}
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

void Aladdin::CAPI::SCard::APDU::LibApplet::RemoveFolder(... array<WORD>^ path) 
{$
    // получить интерфейс LibAPDU
    libapdu::IAppFS& fs = Token()->fs(); 
	try { 
        // выбрать апплет требуемым способом
		if (!initialized) Token()->selectApplet(id); 

		// выбрать и удалить объект каталога
		LibAppletFileFolder(this, path); fs.remove();
    }
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

void Aladdin::CAPI::SCard::APDU::LibApplet::RemoveFile(... array<WORD>^ path) 
{$
    // получить интерфейс LibAPDU
    libapdu::IAppFS& fs = Token()->fs(); 
	try { 
        // выбрать апплет требуемым способом
		if (!initialized) Token()->selectApplet(id); 

		// выбрать и удалить объект файла
		LibAppletFile(this, path); fs.remove();
    }
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}
