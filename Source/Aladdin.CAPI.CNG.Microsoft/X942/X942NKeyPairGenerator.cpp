#include "..\stdafx.h"
#include "X942NKeyPairGenerator.h"
#include "X942Encoding.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X942NKeyPairGenerator.tmh"
#endif 

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace X942 
{
///////////////////////////////////////////////////////////////////////////
// ��������� ���������� �����
///////////////////////////////////////////////////////////////////////////
private ref class ParamAction
{
	// ��������� �����
	private: IntPtr ptrBlob; private: DWORD cbBlob; 

	// �����������
	public: ParamAction(IntPtr ptrBlob, DWORD cbBlob)
	{
		// ��������� ���������� ���������
		this->ptrBlob = ptrBlob; this->cbBlob = cbBlob; 
	}
	// ���������� ��������� �����
	public: void Invoke(CAPI::CNG::Handle^ hKey)
	{
		// ���������� ��������� 
		hKey->SetParam(NCRYPT_DH_PARAMETERS_PROPERTY, IntPtr(ptrBlob), cbBlob, 0); 
	}
}; 
}}}}}

///////////////////////////////////////////////////////////////////////////
// �������� ��������� ������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::NKeyHandle^ 
Aladdin::CAPI::CNG::Microsoft::X942::NKeyPairGenerator::Generate(
	CAPI::CNG::Container^ container, String^ keyOID, DWORD keyType, BOOL exportable) 
{$
	// ������� ��������� 
	ANSI::X942::IParameters^ parameters = (ANSI::X942::IParameters^)Parameters; 

	// ���������� ��������� ������ ������
	DWORD cbBlob = Encoding::GetParametersBlob(parameters, 0, 0); std::vector<BYTE> vecBlob(cbBlob); 

	// �������� ����� ���������� �������
	BCRYPT_DH_PARAMETER_HEADER* pbBlob = (BCRYPT_DH_PARAMETER_HEADER*)&vecBlob[0]; 

	// �������� ��������� ��� ������� ����������
	cbBlob = Encoding::GetParametersBlob(parameters, pbBlob, cbBlob); 

	// ������� ������� ��������� ����������
	ParamAction^ paramAction = gcnew ParamAction(IntPtr(pbBlob), cbBlob); 

	// ������� ������� ��������� ����������
	Action<CAPI::CNG::Handle^>^ action = gcnew Action<CAPI::CNG::Handle^>(
		paramAction, &ParamAction::Invoke
	); 
	// ������������� ���� ������
	return Generate(container, NCRYPT_DH_ALGORITHM, keyType, exportable, action, 0); 
}

