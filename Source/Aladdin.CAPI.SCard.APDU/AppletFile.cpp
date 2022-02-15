#include "StdAfx.h"
#include "Applet.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "AppletFile.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ������ �������� �������
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::SCard::APDU::LibAppletFileObject::Select()
{$
    // �������� ��������� LibAPDU
    libapdu::IAppFS& fs = Applet->Token()->fs(); 
	try {
        // �������� ������ ��� ���� �������
		libapdu::TPath objectPath(path->Length, 0); 

        // ����������� ��� ���������� ����
		for (int i = 0; i < path->Length; i++) objectPath[i] = path[i];

        // ������� ������ �������� �������
		fs.select(objectPath);
    }
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

Aladdin::CAPI::SCard::FileObjectInfo 
Aladdin::CAPI::SCard::APDU::LibAppletFileObject::GetInfo()
{$
    // �������� ��������� LibAPDU
    libapdu::IToken* token = Applet->Token(); Select(); 
	try	{
        // �������� ���������� ������� �������� �������
		libapdu::CFileInfo fi(token->fs().info()); 

        // �������� ��� ������� � ������� �������� �������
		libapdu::TFileAccess userAccess = (libapdu::TFileAccess)token->pin().pathUser().back();

        // ������� ��������� �������
        array<String^>^ readAccessUsers = nullptr; array<String^>^ writeAccessUsers = nullptr;

        // ������� ��� ������� � �������
        if (fi.read  == userAccess) readAccessUsers  = gcnew array<String^> { "USER" }; 
        if (fi.write == userAccess) writeAccessUsers = gcnew array<String^> { "USER" }; 

        // ������� ��������� ����������
		return FileObjectInfo(fi.size, readAccessUsers, writeAccessUsers); 
    }
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

///////////////////////////////////////////////////////////////////////////
// ���� �� �����-�����
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::SCard::APDU::LibAppletFile::LibAppletFile(
	LibApplet^ applet, array<WORD>^ path) : LibAppletFileObject(applet, path) 
{$
    // �������� ��������� LibAPDU
    libapdu::IAppFS& fs = Applet->Token()->fs(); 
    try { 
        // �������� ������ ��� ���� �������
        libapdu::TPath objectPath(path->Length, 0); 

        // ����������� ��� ���������� ����
		for (int i = 0; i < path->Length; i++) objectPath[i] = path[i];

        // ������� ������ �������� �������
	    fs.select(objectPath); libapdu::CFileInfo fi(fs.info());

        // ��������� ������������ ����
        if (fi.type != libapdu::TTypeFile) throw gcnew ArgumentException(); 
    }
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
} 

Aladdin::CAPI::SCard::APDU::LibAppletFile::~LibAppletFile() { $ } 

		
void Aladdin::CAPI::SCard::APDU::LibAppletFile::Read(array<BYTE>^ data, int offset)
{$
    // �������� ��������� LibAPDU
    libapdu::IAppFS& fs = Applet->Token()->fs(); Select(); 
	try {
		// �������� ����� ���������� �������
		libapdu::TBytes buffer(data->Length, 0); 

        // ��������� ������ �� ����� � �����
		fs.read(buffer, offset);

        // ����������� ������ � ���������� �����
		Marshal::Copy(IntPtr(&buffer[0]), data, 0, data->Length); 
	}
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

void Aladdin::CAPI::SCard::APDU::LibAppletFile::Write(array<BYTE>^ data, int offset)
{$
    // �������� ��������� LibAPDU
    libapdu::IAppFS& fs = Applet->Token()->fs(); Select(); 
	try {
		// �������� ����� ���������� �������
		libapdu::TBytes buffer(data->Length, 0); 

        // ����������� ������ � ��������� �����
		Marshal::Copy(data, 0, IntPtr(&buffer[0]), data->Length);

        // �������� ������ �� ������ � ����
		fs.write(buffer, offset); 
	}
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

///////////////////////////////////////////////////////////////////////////
// ������� �� �����-����� 
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::SCard::APDU::LibAppletFileFolder::LibAppletFileFolder(
	LibApplet^ applet, array<WORD>^ path) : LibAppletFileObject(applet, path) 
{$
    // �������� ��������� LibAPDU
    libapdu::IAppFS& fs = Applet->Token()->fs(); 
    try { 
        // �������� ������ ��� ���� �������
        libapdu::TPath objectPath(path->Length, 0); 

        // ����������� ��� ���������� ����
		for (int i = 0; i < path->Length; i++) objectPath[i] = path[i];

        // ������� ������ �������� �������
	    fs.select(objectPath); libapdu::CFileInfo fi(fs.info());

        // ��������� ������������ ����
        if (fi.type != libapdu::TTypeDir) throw gcnew ArgumentException(); 
    }
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
} 

Aladdin::CAPI::SCard::APDU::LibAppletFileFolder::~LibAppletFileFolder() { $ } 

		
array<WORD>^ Aladdin::CAPI::SCard::APDU::LibAppletFileFolder::EnumerateFolders()
{$
    // �������� ��������� LibAPDU
    libapdu::IAppFS& fs = Applet->Token()->fs(); Select(); 
	try {
        // ����������� ������� �������� �������			
        libapdu::TList fileList = fs.list(libapdu::TTypeDir);
		
        // ������� ������ ����������������	
		array<WORD>^ retValue = gcnew array<WORD>((int)fileList.size());
				
        // ��������� ������ ���������������
        for (int i = 0; i < retValue->Length; i++) retValue[i] = fileList[i]; return retValue;
    }
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

array<WORD>^ Aladdin::CAPI::SCard::APDU::LibAppletFileFolder::EnumerateFiles()
{$
    // �������� ��������� LibAPDU
    libapdu::IAppFS& fs = Applet->Token()->fs(); Select(); 
	try {
        // ����������� ������� �������� �������			
        libapdu::TList fileList = fs.list(libapdu::TTypeFile);
		
        // ������� ������ ����������������	
		array<WORD>^ retValue = gcnew array<WORD>((int)fileList.size());
				
        // ��������� ������ ���������������
        for (int i = 0; i < retValue->Length; i++) retValue[i] = fileList[i]; return retValue;
    }
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

Aladdin::CAPI::SCard::IAppletFileFolder^ 
Aladdin::CAPI::SCard::APDU::LibAppletFileFolder::CreateFolder(WORD name, FileObjectInfo info)
{$
    // ��������� ������������ ����� ������� �������� �������
	if (name == 0x0000 || name == 0xFFFF || name == 0x3FFF || name == 0x3F00) 
    {
        // ��� ������ ��������� ����������
        throw gcnew ArgumentException(nullptr);
    }
    // �������� ��������� LibAPDU
    libapdu::IAppFS& fs = Applet->Token()->fs();  
	try {
        // ������� ��� ������� �������� �������
	    libapdu::CFileInfo fi; fi.type = libapdu::TTypeDir; 

        // ������� ��� ������� � ������� �������� �������
        fi.read  = libapdu::TAccessEveryone; 
		fi.write = libapdu::TAccessEveryone; 

		// ������� ������ �������� �������
        Select(); fi.size = 0; fs.create(name, fi); 

        // �������� ������ ��� ���� �������
        array<WORD>^ path = gcnew array<WORD>(Path->Length + 1); 

        // ������� ���� ��� �������
        Array::Copy(Path, 0, path, 0, Path->Length); path[Path->Length] = name; 

        // ������� ��������� ������
        return gcnew LibAppletFileFolder(Applet, path);
    }
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

Aladdin::CAPI::SCard::IAppletFile^ 
Aladdin::CAPI::SCard::APDU::LibAppletFileFolder::CreateFile(WORD name, FileObjectInfo info)
{$
    // ��������� ������������ ����� ������� �������� �������
	if (name == 0x0000 || name == 0xFFFF || name == 0x3FFF || name == 0x3F00) 
    {
        // ��� ������ ��������� ����������
        throw gcnew ArgumentException(nullptr);
    }
    // �������� ��������� LibAPDU
    libapdu::IAppFS& fs = Applet->Token()->fs(); libapdu::IAppPin& pin = Applet->Token()->pin();
	try {
        // ������� ��� ������� �������� �������
		libapdu::CFileInfo fi; fi.type = libapdu::TTypeFile; 

        // ������� ��� ������� � ������� �������� �������
        fi.read = libapdu::TAccessEveryone; fi.write = libapdu::TAccessEveryone; 

        // ��������� ������� ����������������� ������� � �����
        Nullable<bool> readAccess  = info.HasReadAccess ("USER"); 
        Nullable<bool> writeAccess = info.HasWriteAccess("USER");

        // ��� ���������������� ������� � �����
	    if ((readAccess .HasValue && readAccess .Value) || 
            (writeAccess.HasValue && writeAccess.Value))
		{
			// �������� ��� ������� � ������� �������� �������
			libapdu::TFileAccess userAccess = (libapdu::TFileAccess)pin.pathUser().back();

			// ������� ������� ����������������� �������
			if (readAccess .HasValue && readAccess .Value) fi.read  = userAccess;
			if (writeAccess.HasValue && writeAccess.Value) fi.write = userAccess; 
        } 
        // ������� ������ �������� �������
        Select(); fi.size = libapdu::TFileSize(info.ObjectSize); fs.create(name, fi);

        // �������� ������ ��� ���� �������
        array<WORD>^ path = gcnew array<WORD>(Path->Length + 1); 

        // ������� ���� ��� �������
        Array::Copy(Path, 0, path, 0, Path->Length); path[Path->Length] = name; 

        // ������� ��������� ������
        return gcnew LibAppletFile(Applet, path); 
    }
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

Aladdin::CAPI::SCard::IAppletFileFolder^ 
Aladdin::CAPI::SCard::APDU::LibAppletFileFolder::OpenFolder(WORD name)
{$
    // �������� ������ ��� ���� �������
    array<WORD>^ path = gcnew array<WORD>(Path->Length + 1); 

    // ������� ���� ��� �������
    Array::Copy(Path, 0, path, 0, Path->Length); path[Path->Length] = name; 

    // ������� ������� ������ �������� �������
    return gcnew LibAppletFileFolder(Applet, path); 
}

Aladdin::CAPI::SCard::IAppletFile^ 
Aladdin::CAPI::SCard::APDU::LibAppletFileFolder::OpenFile(WORD name)
{$
    // �������� ������ ��� ���� �������
    array<WORD>^ path = gcnew array<WORD>(Path->Length + 1); 

    // ������� ���� ��� �������
    Array::Copy(Path, 0, path, 0, Path->Length); path[Path->Length] = name; 

    // ������� ������� ������ �������� �������
    return gcnew LibAppletFile(Applet, path); 
}

void Aladdin::CAPI::SCard::APDU::LibAppletFileFolder::RemoveFolder(WORD name)
{$
    // �������� ������ ��� ���� �������
    array<WORD>^ path = gcnew array<WORD>(Path->Length + 1); 

    // ������� ���� ��� �������
    Array::Copy(Path, 0, path, 0, Path->Length); path[Path->Length] = name; 

    // �������� ��������� LibAPDU
    libapdu::IAppFS& fs = Applet->Token()->fs(); 
	try {
		// ������� � ������� ������ ��������
		LibAppletFileFolder(Applet, path); fs.remove();
	}
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

void Aladdin::CAPI::SCard::APDU::LibAppletFileFolder::RemoveFile(WORD name)
{$
    // �������� ������ ��� ���� �������
    array<WORD>^ path = gcnew array<WORD>(Path->Length + 1); 

    // ������� ���� ��� �������
    Array::Copy(Path, 0, path, 0, Path->Length); path[Path->Length] = name; 

    // �������� ��������� LibAPDU
    libapdu::IAppFS& fs = Applet->Token()->fs(); 
	try {	
		// ������� � ������� ������ �����
		LibAppletFile(Applet, path); fs.remove();
    }
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

///////////////////////////////////////////////////////////////////////
// �������� ������� �������
///////////////////////////////////////////////////////////////////////
Aladdin::CAPI::SCard::IAppletFileFolder^ 
Aladdin::CAPI::SCard::APDU::LibApplet::OpenFolder(... array<WORD>^ path)
{$
	try { 
        // ������� ������ ��������� ��������
		if (!initialized) Token()->selectApplet(id); 

		// ������� ������� ������ �������� �������
		return gcnew LibAppletFileFolder(this, path); 
	}
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

Aladdin::CAPI::SCard::IAppletFile^ 
Aladdin::CAPI::SCard::APDU::LibApplet::OpenFile(... array<WORD>^ path)
{$
	try {
        // ������� ������ ��������� ��������
		if (!initialized) Token()->selectApplet(id); 

		// ������� ������� ������ �������� �������
		return gcnew LibAppletFile(this, path); 
	}
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

void Aladdin::CAPI::SCard::APDU::LibApplet::RemoveFolder(... array<WORD>^ path) 
{$
    // �������� ��������� LibAPDU
    libapdu::IAppFS& fs = Token()->fs(); 
	try { 
        // ������� ������ ��������� ��������
		if (!initialized) Token()->selectApplet(id); 

		// ������� � ������� ������ ��������
		LibAppletFileFolder(this, path); fs.remove();
    }
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

void Aladdin::CAPI::SCard::APDU::LibApplet::RemoveFile(... array<WORD>^ path) 
{$
    // �������� ��������� LibAPDU
    libapdu::IAppFS& fs = Token()->fs(); 
	try { 
        // ������� ������ ��������� ��������
		if (!initialized) Token()->selectApplet(id); 

		// ������� � ������� ������ �����
		LibAppletFile(this, path); fs.remove();
    }
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}
