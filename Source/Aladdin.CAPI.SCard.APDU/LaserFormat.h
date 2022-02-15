#pragma once 

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU { namespace Laser
{
///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ���-����
///////////////////////////////////////////////////////////////////////////////
public ref class ComplexityParameters : SCard::FormatParameters
{
	// �����������
	public: ComplexityParameters(int ordinal) : SCard::FormatParameters(ordinal) 
	{
		// ����������� ����� ��������
		MinChars = gcnew FormatParameter<Int32>(
			1, 4, gcnew FormatValidator::Range(4, 16)
		);   
		// ������������ ����� ��������
		MaxChars =	gcnew FormatParameter<Int32>(
			2, 16, gcnew FormatValidator::Range(4, 16)
		);   
		// ����������� ����� ���� � ����
		MinAlphaNumerics = gcnew FormatParameter<Int32>(
			3, 0, gcnew FormatValidator::Range(0, 16)
		);   
		// ����������� ����� �� ���� � ����
		MinNonAlphaNumerics = gcnew FormatParameter<Int32>(
			4, 0, gcnew FormatValidator::Range(0, 16)
		);   
		// ����������� ����� ����
		MinDigits = gcnew FormatParameter<Int32>(
			5, 0, gcnew FormatValidator::Range(0, 16)
		);   
		// ����������� ����� ����
		MinAlphabetics = gcnew FormatParameter<Int32>(
			6, 0, gcnew FormatValidator::Range(0, 16)
		);   
		// ����������� ����� ���� � ������� ��������
		MinUppers = gcnew FormatParameter<Int32>(
			7, 0, gcnew FormatValidator::Range(0, 16)
		);   
		// ����������� ����� ���� � ������� ��������
		MinLowers =	gcnew FormatParameter<Int32>(
			8, 0, gcnew FormatValidator::Range(0, 16)
		);   
		// ������������ ����� ���������� �������� � ���-����
		RepeatedChars = gcnew FormatParameter<Int32>(
			9, 16, gcnew FormatValidator::Range(0, 16)
		);   
		// ������������ ����� ���������� �������� � ���-����
		SequenceChars =	gcnew FormatParameter<Int32>(
			10, 16, gcnew FormatValidator::Range(0, 16)
		);   
	}
	// ��������� ��������� ���-����
	public: initonly FormatParameter<Int32>^ MinChars;   
	public: initonly FormatParameter<Int32>^ MaxChars;   
	public: initonly FormatParameter<Int32>^ MinAlphaNumerics;   
	public: initonly FormatParameter<Int32>^ MinNonAlphaNumerics;   
	public: initonly FormatParameter<Int32>^ MinDigits;   
	public: initonly FormatParameter<Int32>^ MinAlphabetics;   
	public: initonly FormatParameter<Int32>^ MinUppers;   
	public: initonly FormatParameter<Int32>^ MinLowers;   
	public: initonly FormatParameter<Int32>^ RepeatedChars;   
	public: initonly FormatParameter<Int32>^ SequenceChars;   
};	

///////////////////////////////////////////////////////////////////////////////
// ��������� ������������� ���-����
///////////////////////////////////////////////////////////////////////////////
public ref class PinParameters : SCard::FormatParameters
{
	// �����������
	public: PinParameters(int ordinal) : SCard::FormatParameters(ordinal) 
	{
		// ��������� ���-����
		Complexity = gcnew ComplexityParameters(1);   

		// ������������ ����� ����� ���-����
		MaxAttempts = gcnew FormatParameter<Int32>(
			2, 10, gcnew FormatValidator::Range(1, 15)
		);   
	}
	// ��������� ������������� ���-����
	public: initonly ComplexityParameters^   Complexity;   
	public: initonly FormatParameter<Int32>^ MaxAttempts;   
}; 

public ref class AdminPinParameters : PinParameters
{
	// �����������
	public: AdminPinParameters(int ordinal) : PinParameters(ordinal) 
	{
		// ������� ������� ���-����
		History = gcnew FormatParameter<Int32>(
			3, 0, gcnew FormatValidator::Range(0, 255)
		);   
	}
	// ��������� ������������� ���-����
	public: initonly FormatParameter<Int32>^ History;   
}; 

public ref class UserPinParameters : PinParameters
{
	// �����������
	public: UserPinParameters(int ordinal) : PinParameters(ordinal) 
	{
		// ������� ������� ���-����
		History = gcnew FormatParameter<Int32>(
			3, 0, gcnew FormatValidator::Range(0, 255)
		);   
		// ������������ ����� �������������
		MaxUnlocks = gcnew FormatParameter<Int32>(
			4, 0, gcnew FormatValidator::Range(0, 15)
		);   
		// ������������� ����� ���-���� ����� ������� �����
		MustFirstChange = gcnew FormatParameter<Boolean>(5, false); 

		// ������������� ����� ���-���� ����� �������������
		MustUnlockChange = gcnew FormatParameter<Boolean>(6, false); 
	}
	// ��������� ������������� ���-����
	public: initonly FormatParameter<Int32>^   History;   
	public: initonly FormatParameter<Int32>^   MaxUnlocks;   
	public: initonly FormatParameter<Boolean>^ MustFirstChange; 
	public: initonly FormatParameter<Boolean>^ MustUnlockChange; 

}; 

public ref class DSPinParameters : PinParameters
{
	// �����������
	public: DSPinParameters(int ordinal) : PinParameters(ordinal) 
	{
		// ������������ ����� �������������
		MaxUnlocks = gcnew FormatParameter<Int32>(3, 
			0, gcnew FormatValidator::Range(0, 15)
		);   
	}
	// ��������� ������������� ���-����
	public: initonly FormatParameter<Int32>^ MaxUnlocks;   
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������� �������������� ��������������
///////////////////////////////////////////////////////////////////////////////
public ref class BiometricParameters : SCard::FormatParameters
{
	// �����������
	public: BiometricParameters(int ordinal) : SCard::FormatParameters(ordinal) 
	{
		// ������������ ����� �������������
		MaxUnlocks = gcnew FormatParameter<Int32>(
			1, 0, gcnew FormatValidator::Range(0, 15)
		);   
		// ������������ ����� ���������� ��� ��������������
		MaxFingers = gcnew FormatParameter<Int32>(
			2, 1, gcnew FormatValidator::Range(1, 10)
		);   
		// ���������� �������� ����������� ����������
		ImageQuality = gcnew FormatParameter<Int32>(
			3, 51, gcnew FormatValidator::Range(0, 100)
		);   
		// FAR �������������� �������������� (21474836 � 1:100, 
		// 2147483 � 1:1000, 214748 � 1:10000, 21474 � 1:100000, 
		// 2147 � 1:1000000)
		EnrollFar = gcnew FormatParameter<Int32>(
			4, 214748, gcnew FormatValidator::Range(2147, 21474836)
		);   
	}
	// ��������� �������������� ��������������
	public: initonly FormatParameter<Int32>^ MaxUnlocks;   
	public: initonly FormatParameter<Int32>^ MaxFingers;   
	public: initonly FormatParameter<Int32>^ ImageQuality;   
	public: initonly FormatParameter<Int32>^ EnrollFar;   
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������������
///////////////////////////////////////////////////////////////////////////////
public ref class AdminParameters : SCard::FormatParameters
{
	// �����������
	public: AdminParameters(int ordinal) : SCard::FormatParameters(ordinal) 
	{
		// ������������� ��������� "������-�����"
		UseResponse = gcnew FormatParameter<Boolean>(1, false);   

		// ��������� ������������� ���-����
		PIN = gcnew AdminPinParameters(2); 
	}
	// ��������� ��������������
	public: initonly FormatParameter<Boolean>^ UseResponse;   
	public: initonly AdminPinParameters^       PIN; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ��� �������������� ������������
///////////////////////////////////////////////////////////////////////////////
public enum class UserLoginType { 
	None		= 0,  // �����������
	Pin			= 1,  // PIN-��������������
	Response	= 2,  // PIN-�������������� "������-�����"
	Bio			= 3,  // �������������� ��������������
	PinOrBio	= 4,  // PIN- ��� �������������� ��������������
	PinAndBio	= 5   // PIN-  �  �������������� ��������������
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ������������
///////////////////////////////////////////////////////////////////////////////
public ref class UserParameters : SCard::FormatParameters
{
	// �����������
	public: UserParameters(int ordinal) : SCard::FormatParameters(ordinal) 
	{
		// ��� ��������������
		LoginType =	gcnew FormatParameter<UserLoginType>(
			1, UserLoginType::Pin, gcnew FormatValidator::Range(1, 5)
		);   
		// ���-���
		DefaultPIN = gcnew FormatParameter<String^>(
			2, "11111111", gcnew FormatValidator::Length(4, 16, false)
		);   
		// ��������� ������������� ���-����
		PIN = gcnew UserPinParameters  (3); 

		// ��������� �������������� ��������������
		Bio = gcnew BiometricParameters(4); 
	}
	// ��������� ������������
	public: initonly FormatParameter<UserLoginType>^ LoginType;   
	public: initonly FormatParameter<String^>^       DefaultPIN;   
	public: initonly UserPinParameters  ^			 PIN; 
	public: initonly BiometricParameters^			 Bio; 
}; 

///////////////////////////////////////////////////////////////////////////
// ������ ������������ ������ �����������
///////////////////////////////////////////////////////////////////////////
public enum class ProviderCacheMode { Off = 0, Prompt = 1, On = 2 }; 

///////////////////////////////////////////////////////////////////////////
// ��������� DS
///////////////////////////////////////////////////////////////////////////
public ref class DSParameters : SCard::FormatParameters
{
	// �����������
	public: DSParameters(int ordinal) : SCard::FormatParameters(ordinal) 
	{
		// ��������� ���-���� � ���-����
		PIN = gcnew DSPinParameters(1);   
		PUK = gcnew DSPinParameters(2);   

		// ������������ ����� 1024-������ ������
		Max1024Keys = gcnew FormatParameter<Int32>(
			3, 2, gcnew FormatValidator::Range(2, 4)
		);   
		// ������������ ����� 2048-������ ������
		Max2048Keys = gcnew FormatParameter<Int32>(
			4, 2, gcnew FormatValidator::Range(2, 4)
		);   
		// ������������� � ���������������� PIN
		UserSynchronize = gcnew FormatParameter<Boolean>(5, false); 

		// c����� ������������ ������ �����������
		CacheMode = gcnew FormatParameter<ProviderCacheMode>(
			6, ProviderCacheMode::Off
		); 
	}
	// ��������� DS
	public: initonly DSPinParameters^					 PIN;   
	public: initonly DSPinParameters^					 PUK;   
	public: initonly FormatParameter<Int32>^			 Max1024Keys;   
	public: initonly FormatParameter<Int32>^			 Max2048Keys;   
	public: initonly FormatParameter<Boolean>^			 UserSynchronize; 
	public: initonly FormatParameter<ProviderCacheMode>^ CacheMode; 
}; 

///////////////////////////////////////////////////////////////////////////
// ��������� �������������� �������
///////////////////////////////////////////////////////////////////////////
public ref class FormatParameters : SCard::FormatParameters
{
	// �����������
	public: FormatParameters() : SCard::FormatParameters() 
	{
		// ����� �����-�����
		Label =	gcnew FormatParameter<String^>(
			1, "JaCarta PKI", gcnew FormatValidator::Length(1, 32, true)
		);   
		// ��������� �������������� � ������������
		Admin = gcnew AdminParameters(2); 
		User  = gcnew UserParameters (3); 

		// ��������� DS
		DS = gcnew DSParameters(4); 

		// ����� �������� ���-���� � ����
		ExpiredTimePIN = gcnew FormatParameter<Int32>(
			5, 0, gcnew FormatValidator::Range(0, 9999)
		);   
		// ����� ����������� PIN � �������
		CacheTimePIN = gcnew FormatParameter<Int32>(
			6, 0, gcnew FormatValidator::Range(0, 9999)
		);   
		// ���-��� ���������
		ActivationPIN = gcnew FormatParameter<String^>(
			7, nullptr, gcnew FormatValidator::Length(4, 16, false)
		);   
		// ���-��� �����������
		DeactivationPIN = gcnew FormatParameter<String^>(
			8, nullptr, gcnew FormatValidator::Length(4, 16, false)
		);   
	}
	// ��������� �������������� �������
	public: initonly FormatParameter<String^>^	Label;   
	public: initonly AdminParameters^			Admin; 
	public: initonly UserParameters^			User; 
	public: initonly DSParameters^				DS; 
	public: initonly FormatParameter<Int32>^	ExpiredTimePIN;   
	public: initonly FormatParameter<Int32>^	CacheTimePIN;   
	public: initonly FormatParameter<String^>^	ActivationPIN;   
	public: initonly FormatParameter<String^>^	DeactivationPIN;   
}; 
}}}}}
