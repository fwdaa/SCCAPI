#pragma once
#include "Container.h"

namespace Aladdin { namespace CAPI { namespace CSP 
{
	//////////////////////////////////////////////////////////////////////////////
	// �������� ��������� ������
	//////////////////////////////////////////////////////////////////////////////
	public ref class KeyPairGenerator abstract : CAPI::KeyPairGenerator
    {
		// ��������� ������
		private: IParameters^ parameters; 

		// �����������
		public: KeyPairGenerator(CSP::Provider^ provider, 
			SecurityObject^ scope, IRand^ rand, IParameters^ parameters) 
			
			// ��������� ���������� ���������
			: CAPI::KeyPairGenerator(provider, scope, rand) { this->parameters = parameters; }

        // ������������ ���������
		public: property CSP::Provider^ Provider 
		{ 
			// ������������ ���������
			CSP::Provider^ get() { return (CSP::Provider^)Factory; }
		}
        // ��������� ���������
		public: property IParameters^ Parameters { IParameters^ get() { return parameters; }}

		// ������������� ���� ������
		public: virtual KeyPair^ Generate(array<BYTE>^ keyID, 
			String^ keyOID, KeyUsage keyUsage, KeyFlags keyFlags) override; 

		// ������������� ���� ������
		public: virtual KeyPair^ Generate(String^ keyOID, KeyUsage keyUsage); 

		// ������������� ���� ������
		protected: virtual KeyHandle^ Generate(Container^ container, 
			String^ keyOID, DWORD keyType, DWORD keyFlags) = 0; 

		// ������������� ���� ������
		protected: KeyHandle^ Generate(Container^ container, ALG_ID algID, DWORD flags); 
	};
}}}