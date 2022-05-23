#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace X957
{
	//////////////////////////////////////////////////////////////////////////////
	// �������� ��������� ������
	//////////////////////////////////////////////////////////////////////////////
    public ref class NKeyPairGenerator : CAPI::CNG::NKeyPairGenerator
    {
		// �����������
		public: NKeyPairGenerator(CAPI::CNG::NProvider^ provider, 
			SecurityObject^ scope, IRand^ rand, ANSI::X957::IParameters^ parameters)

			// ��������� ���������� ���������
			: CAPI::CNG::NKeyPairGenerator(provider, scope, rand, parameters) {}

		// ������������� ���� ������
		protected: virtual CAPI::CNG::NKeyHandle^ Generate(
            CAPI::CNG::Container^ container, 
            String^ keyOID, DWORD keyType, BOOL exportable) override; 
    };
}}}}}
