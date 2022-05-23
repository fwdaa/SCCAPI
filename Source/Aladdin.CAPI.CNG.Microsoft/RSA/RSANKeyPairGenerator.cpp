#include "..\stdafx.h"
#include "RSANKeyPairGenerator.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSANKeyPairGenerator.tmh"
#endif 

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace RSA 
{
///////////////////////////////////////////////////////////////////////////
// ��������� ���������� �����
///////////////////////////////////////////////////////////////////////////
private ref class SetParametersAction
{
	// �����������
	public: SetParametersAction(int bits)
	
		// ��������� ���������� ���������
		{ this->bits = bits; } private: int bits;

	// ���������� ��������� �����
	public: void Invoke(CAPI::CNG::Handle^ hKey)
	{
		// ������� �������� ���������
		DWORD value = bits; DWORD cbValue = sizeof(value); 

		// ���������� ������ ����� � �����
		hKey->SetParam(NCRYPT_LENGTH_PROPERTY, IntPtr(&value), cbValue, 0); 
	}
}; 
}}}}}

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::NKeyHandle^ 
Aladdin::CAPI::CNG::Microsoft::RSA::NKeyPairGenerator::Generate(
	CAPI::CNG::Container^ container, String^ keyOID, DWORD keyType, BOOL exportable) 
{$
	// ������� ��������� ����� �����
	int bits = ((IKeySizeParameters^)Parameters)->KeyBits;

	// ������� ������� ��������� ����������
	SetParametersAction^ paramAction = gcnew SetParametersAction(bits); 

    // ������� ������� ��������� ����������
    Action<CAPI::CNG::Handle^>^ action = gcnew Action<CAPI::CNG::Handle^>(
        paramAction, &SetParametersAction::Invoke
    ); 
	// ������������� ����� 
	return Generate(container, NCRYPT_RSA_ALGORITHM, keyType, exportable, action, 0); 
}

