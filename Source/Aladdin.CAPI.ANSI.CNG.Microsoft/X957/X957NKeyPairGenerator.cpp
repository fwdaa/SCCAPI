#include "..\stdafx.h"
#include "..\PrimitiveProvider.h"
#include "X957NKeyPairGenerator.h"
#include "X957BKeyPairGenerator.h"
#include "X957Encoding.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X957NKeyPairGenerator.tmh"
#endif 

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace X957 
{
///////////////////////////////////////////////////////////////////////////
// ��������� ���������� �����
///////////////////////////////////////////////////////////////////////////
private ref class SetParametersAction
{
	// ��������� �����
	private: IntPtr ptrBlob; private: DWORD cbBlob; 

	// �����������
	public: SetParametersAction(IntPtr ptrBlob, DWORD cbBlob)
	{
		// ��������� ���������� ���������
		this->ptrBlob = ptrBlob; this->cbBlob = cbBlob; 
	}
	// ���������� ��������� �����
	public: void Invoke(CAPI::CNG::Handle^ hKey)
	{
		// ���������� ��������� 
		hKey->SetParam(BCRYPT_DSA_PRIVATE_BLOB, IntPtr(ptrBlob), cbBlob, 0); 
	}
}; 
}}}}}}

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::NKeyHandle^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::X957::NKeyPairGenerator::Generate(
	CAPI::CNG::Container^ container, String^ keyOID, DWORD keyType, BOOL exportable) 
{$
	// ��������� ��� �����
	if (keyType != AT_SIGNATURE) throw gcnew Win32Exception(NTE_BAD_TYPE); 

	// ������� ��� ���������
	PrimitiveProvider factory; String^ algName = NCRYPT_DSA_ALGORITHM; 

    // �������� ��������� �����
    ANSI::X957::IParameters^ parameters = (ANSI::X957::IParameters^)Parameters; 

	// ������� ����������� �������� ���������
	BKeyPairGenerator generator(%factory, nullptr, Rand, factory.Provider, parameters); 

	// ������������� ����������� ���� ������
	Using<KeyPair^> keyPair(generator.Generate(keyOID));

	// ������������� ��� ������
	ANSI::X957::IPublicKey ^ publicKeyDSA  = (ANSI::X957::IPublicKey^ )keyPair.Get()->PublicKey; 
	ANSI::X957::IPrivateKey^ privateKeyDSA = (ANSI::X957::IPrivateKey^)keyPair.Get()->PrivateKey; 

	// ���������� ��������� ������ ������
	DWORD cbBlob = Encoding::GetKeyPairBlob(publicKeyDSA, privateKeyDSA, 0, 0); 

	// �������� ����� ���������� �������
	std::vector<BYTE> vecBlob(cbBlob); BCRYPT_DSA_KEY_BLOB* pbBlob = (BCRYPT_DSA_KEY_BLOB*)&vecBlob[0]; 

	// �������� ��������� ��� ������� �����
	cbBlob = Encoding::GetKeyPairBlob(publicKeyDSA, privateKeyDSA, pbBlob, cbBlob); 

	// ������� ������� ��������� ����������
	SetParametersAction^ paramAction = gcnew SetParametersAction(IntPtr(pbBlob), cbBlob); 

	// ������� ������� ��������� ����������
	Action<CAPI::CNG::Handle^>^ action = gcnew Action<CAPI::CNG::Handle^>(
        paramAction, &SetParametersAction::Invoke
    ); 
	// ������������� ���� ������
	return Generate(container, NCRYPT_DSA_ALGORITHM, keyType, exportable, action, 0); 
}

