#pragma once 

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU { namespace Cryptotoken
{
///////////////////////////////////////////////////////////////////////////
// ��������� �������������� �������
///////////////////////////////////////////////////////////////////////////
public ref class FormatParameters : SCard::FormatParameters
{
	// �����������
	public: FormatParameters() 
	{
		// ����� �����-�����
		Label = gcnew FormatParameter<String^>(
			1, "JaCarta ����", gcnew FormatValidator::Length(1, 32)
		); 
		// ���-��� ������������
		UserPIN = gcnew FormatParameter<String^>(
			2, "1234567890", gcnew FormatValidator::Length(6, 30, false)
		); 
	}
	// ��������� �������������� �������
	public: initonly FormatParameter<String^>^ Label; 
	public: initonly FormatParameter<String^>^ UserPIN; 
}; 
}}}}}
