#pragma once
#include "Container.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
	//////////////////////////////////////////////////////////////////////////////
	// �������� ��������� ������
	//////////////////////////////////////////////////////////////////////////////
	public ref class BKeyPairGenerator abstract : Software::KeyPairGenerator
    {
		// ������� ���������� � ����������������� ��������
		private: Using<BProviderHandle^> hProvider;

		// �����������
		protected: BKeyPairGenerator(CAPI::Factory^ factory, SecurityObject^ scope, 
			IRand^ rand, String^ provider, String^ alg, DWORD flags) 
			
			// ��������� ���������� ���������
			: Software::KeyPairGenerator(factory, scope, rand), 

				// ������� ���������� ���������
				hProvider(gcnew BProviderHandle(provider, alg, flags)) {}

		// ��������� ������������������ ���������
		protected: property BProviderHandle^ Handle 
		{ 
			// ��������� ������������������ ���������
			BProviderHandle^ get() { return hProvider.Get(); }
		}
	};
	//////////////////////////////////////////////////////////////////////////////
	// �������� ��������� ������
	//////////////////////////////////////////////////////////////////////////////
    public ref class NKeyPairGenerator abstract : KeyPairGenerator
    {
		// ��������� ������
		private: IParameters^ parameters; 

		// �����������
		protected: NKeyPairGenerator(NProvider^ provider, 
			SecurityObject^ scope, IRand^ rand, IParameters^ parameters)
			
			// ��������� ���������� ���������
			: KeyPairGenerator(provider, scope, rand) { this->parameters = parameters; }

        // ����������������� ���������
		public: property NProvider^	Provider 
		{ 
			// ����������������� ���������
			NProvider^ get() { return (NProvider^)Factory; }
		}
		// ��������� ������
		public: property IParameters^ Parameters { IParameters^	get() { return parameters; }}

		// ������������� ���� ������
		public: virtual KeyPair^ Generate(array<BYTE>^ keyID, 
			String^ keyOID, KeyUsage keyUsage, KeyFlags keyFlags) override; 

		// ������������� ���� ������
		public: virtual KeyPair^ Generate(String^ keyOID, KeyUsage keyUsage); 

		// ������������� ���� ������
		protected: virtual NKeyHandle^ Generate(Container^ container, 
			String^ keyOID, DWORD keyType, BOOL exportable) = 0; 

		// ������������� ���� ������
		protected: NKeyHandle^ Generate(Container^ container, String^ alg, 
			DWORD keyType, BOOL exportable, Action<Handle^>^ action, DWORD flags
		); 
    };
}}}