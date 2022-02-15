#pragma once 

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU { namespace Pro
{
///////////////////////////////////////////////////////////////////////////
// ������������ ��������� �������� � ���-����
///////////////////////////////////////////////////////////////////////////
public enum class CharPermissibility { DontCare = 0, Forbid = 1, Enforce = 2 }; 

///////////////////////////////////////////////////////////////////////////
// ������ ������������ ������ �����������
///////////////////////////////////////////////////////////////////////////
public enum class ProviderCacheMode { Off = 0, Login = 1, On = 2 }; 

///////////////////////////////////////////////////////////////////////////
// ��������� ��������� ���-����
///////////////////////////////////////////////////////////////////////////
public ref class PinComplexity : SCard::FormatParameters
{
	// �����������
	public: PinComplexity(int ordinal) : SCard::FormatParameters(ordinal) 
	{
		// ������� ������������� ����
		Digits = gcnew FormatParameter<CharPermissibility>(
			1, CharPermissibility::DontCare, 
			gcnew FormatValidator::Range(0, 2)
		);   
	    // ������� ������������� �������� �������� ��������
		Uppers = gcnew FormatParameter<CharPermissibility>(
			2, CharPermissibility::DontCare, 
			gcnew FormatValidator::Range(0, 2)
		);   
		// ������� ������������� �������� ������� ��������
		Lowers = gcnew FormatParameter<CharPermissibility>(
			3, CharPermissibility::DontCare, 
			gcnew FormatValidator::Range(0, 2)
		);   
		// ������� ������������� ����������� ��������
		Specials = gcnew FormatParameter<CharPermissibility>(
			4, CharPermissibility::DontCare, 
			gcnew FormatValidator::Range(0, 2)
		);   
		// ������������ ����� ���������� ������� � ���-����
		RepeatedChars = gcnew FormatParameter<Int32>(
			5, 3, gcnew FormatValidator::Range(0, 16)
		); 
	}
	// ��������� ��������� ���-����
    public: initonly FormatParameter<CharPermissibility>^ Digits;   
	public: initonly FormatParameter<CharPermissibility>^ Uppers;   
	public: initonly FormatParameter<CharPermissibility>^ Lowers;   
	public: initonly FormatParameter<CharPermissibility>^ Specials;   
    public: initonly FormatParameter<Int32>^              RepeatedChars; 
}; 
///////////////////////////////////////////////////////////////////////////
// ��������� ������������� ���-����
///////////////////////////////////////////////////////////////////////////
public ref class PinParameters : SCard::FormatParameters
{
	// �����������
	public: PinParameters(int ordinal) : SCard::FormatParameters(ordinal) 
	{
		// ��������� ���������
		Complexity = gcnew PinComplexity(1); 

		// ������ ���� �������
		History = gcnew FormatParameter<Int32>(
			2, 10, gcnew FormatValidator::Range(0,  16)
		); 
		// ����������� ����� ������������� � ����
		MinAge = gcnew FormatParameter<Int32>(
			3, 0, gcnew FormatValidator::Range(0, 1000)
		); 
		// ������������ ����� ������������� � ����
		MaxAge = gcnew FormatParameter<Int32>(
			4, 1000, gcnew FormatValidator::Range(0, 1000)
		); 
		// ����� ����������� � ������������� ����� � ����
		WarningAge = gcnew FormatParameter<Int32>(
			5, 0, gcnew FormatValidator::Range(0, 1000)
		); 
	}
	// ��������� ������������� ���-����
	public: initonly PinComplexity^          Complexity; 
	public: initonly FormatParameter<Int32>^ History; 
	public: initonly FormatParameter<Int32>^ MinAge; 
	public: initonly FormatParameter<Int32>^ MaxAge; 
	public: initonly FormatParameter<Int32>^ WarningAge; 
}; 

///////////////////////////////////////////////////////////////////////////
// ��������� ��������������
///////////////////////////////////////////////////////////////////////////
public ref class AdminParameters : SCard::FormatParameters
{
	// �����������
	public: AdminParameters(int ordinal) : SCard::FormatParameters(ordinal) 
	{
		// ������������ ����� ������� ����� ���-����
		MaxAttempts = gcnew FormatParameter<Int32>(
			1, 10, gcnew FormatValidator::Range(1, 15)
		); 
	}
	// ��������� ��������������
    public: initonly FormatParameter<Int32>^ MaxAttempts; 
};

///////////////////////////////////////////////////////////////////////////
// ��������� ������������
///////////////////////////////////////////////////////////////////////////
public ref class UserParameters : SCard::FormatParameters
{
	// �����������
	public: UserParameters(int ordinal) : SCard::FormatParameters(ordinal) 
	{
		// ���-��� 
		DefaultPIN = gcnew FormatParameter<String^>(
			1, "1234567890", gcnew FormatValidator::Length(4, 20)
		); 
		// ������������ ����� ������� ����� ���-����
		MaxAttempts = gcnew FormatParameter<Int32>(
			2, 10, gcnew FormatValidator::Range(1, 15)
		); 
		// ����������� ������ ���-���� 
		MinLengthPIN = gcnew FormatParameter<Int32>(
			3, 6, gcnew FormatValidator::Range(4, 20)
		); 
		// ������������� ����� ���-���� ��� ������ �����
		MustFirstChange = gcnew FormatParameter<Boolean>(4, false);  
	}
	// ��������� ������������
	public: initonly FormatParameter<String^>^ DefaultPIN; 
    public: initonly FormatParameter<Int32>^   MaxAttempts; 
    public: initonly FormatParameter<Int32>^   MinLengthPIN; 
	public: initonly FormatParameter<Boolean>^ MustFirstChange;  
};

///////////////////////////////////////////////////////////////////////////
// ��������� �������������� �������
///////////////////////////////////////////////////////////////////////////
public ref class FormatParameters : SCard::FormatParameters
{
	// �����������
	public: FormatParameters() : SCard::FormatParameters() 
	{
		// ����� ��������������
		FormatKey     = gcnew FormatParameter<String^>(1, nullptr); 
		NextFormatKey = gcnew FormatParameter<String^>(2, nullptr); 

		// ����� �����-�����
		Label = gcnew FormatParameter<String^>(
			3, "eToken", gcnew FormatValidator::Length(1, 32)
		); 
		// ��������� FIPS � 2048-������ ������
		FIPS    = gcnew FormatParameter<Boolean>(4, false); 
		RSA2048 = gcnew FormatParameter<Boolean>(5, false); 

		// ��������� �������������� � ������������
		Admin = gcnew AdminParameters(6); 
		User  = gcnew UserParameters (7); 

		// ��������� ������������� ���-����
		PIN = gcnew PinParameters(8); 

		// ������ ����������� ������ �����������
		CacheMode = gcnew FormatParameter<Pro::ProviderCacheMode>(
			9, ProviderCacheMode::Login, gcnew FormatValidator::Range(0, 2)
		); 
	}
	// ��������� �������������� �������
	public: initonly FormatParameter<String^>^					FormatKey; 
	public: initonly FormatParameter<String^>^					NextFormatKey; 
	public: initonly FormatParameter<String^>^					Label; 
    public: initonly FormatParameter<Boolean>^					FIPS; 
    public: initonly FormatParameter<Boolean>^					RSA2048; 
	public: initonly AdminParameters^							Admin; 
	public: initonly UserParameters^							User; 
	public: initonly PinParameters^								PIN; 
	public: initonly FormatParameter<Pro::ProviderCacheMode>^	CacheMode; 
}; 
}}}}}

