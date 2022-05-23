#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace RSA
{
	//////////////////////////////////////////////////////////////////////////////
	// �������� ��������� ������
	//////////////////////////////////////////////////////////////////////////////
    public ref class NKeyPairGenerator : CAPI::CNG::NKeyPairGenerator
    {
		// �����������
		public: NKeyPairGenerator(CAPI::CNG::NProvider^ provider, 
			SecurityObject^ scope, IRand^ rand, ANSI::RSA::IParameters^ parameters)

			// ��������� ���������� ���������
			: CAPI::CNG::NKeyPairGenerator(provider, scope, rand, parameters) 
		{
			// ��������� �������� ����������
			if (parameters->PublicExponent != Math::BigInteger::ValueOf(0x10001L))
			{
				// ��� ������ ��������� ����������
				throw gcnew NotSupportedException(); 
			}
		}
		// ������������� ���� ������
		protected: virtual CAPI::CNG::NKeyHandle^ Generate(
            CAPI::CNG::Container^ container, 
            String^ keyOID, DWORD keyType, BOOL exportable) override; 
    };
}}}}}
