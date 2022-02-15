#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
    ///////////////////////////////////////////////////////////////////////
    // ������������� �������� ����������
    ///////////////////////////////////////////////////////////////////////
	public ref class BEncipherment abstract : CAPI::Encipherment
	{	
		// ��������� ���������
		private: Using<BProviderHandle^> hProvider; 

		// �����������
		protected: BEncipherment(String^ provider, String^ name, DWORD flags)

			// ��������� ��������� ���������� ���������
			: hProvider(gcnew BProviderHandle(provider, name, flags)) {} 

		// ������������� �������� ����
		protected: virtual BKeyHandle^ ImportPublicKey(
			BProviderHandle^ hProvider, IPublicKey^ publicKey) = 0; 

		// ����������� ������
		protected: virtual array<BYTE>^ Encrypt(BKeyHandle^ hPublicKey, array<BYTE>^ data)
		{
			// ����������� ������
			return hPublicKey->Encrypt(IntPtr::Zero, data, 0); 
		}
		// ����������� ������
		public: virtual array<BYTE>^ Encrypt(
			IPublicKey^ publicKey, IRand^ rand, array<BYTE>^ data) override; 
	};
	public ref class BDecipherment abstract : CAPI::Decipherment
	{	
		// ��������� ���������
		private: Using<BProviderHandle^> hProvider; 

		// �����������
		protected: BDecipherment(String^ provider, String^ name, DWORD flags)

			// ��������� ��������� ���������� ���������
			: hProvider(gcnew BProviderHandle(provider, name, flags)) {} 

		// ������������� ������ ����
		protected: virtual BKeyHandle^ ImportPrivateKey(
			BProviderHandle^ hProvider, IPrivateKey^ privateKey) = 0; 

		// ������������ ������
		protected: virtual array<BYTE>^ Decrypt(BKeyHandle^ hPrivateKey, array<BYTE>^ data)
		{
			// ������������ ������
			return hPrivateKey->Decrypt(IntPtr::Zero, data, 0); 
		}
		// ������������ ������
		public: virtual array<BYTE>^ Decrypt(IPrivateKey^ privateKey, array<BYTE>^ data) override; 
	};
	public ref class NEncipherment abstract : CAPI::Encipherment
	{
		// �����������
		protected: NEncipherment(NProvider^ provider) 
		
			// ��������� ���������� ���������
			{ this->provider = RefObject::AddRef(provider); } private: NProvider^ provider; 

		// ����������
		public: virtual ~NEncipherment() { RefObject::Release(provider); }

		// ������������ ���������
		public: property NProvider^ Provider { NProvider^ get() { return provider; }}

		// ����������� ������
		protected: virtual array<BYTE>^ Encrypt(NKeyHandle^ hPublicKey, array<BYTE>^ data)
		{
			// ����������� ������
			return hPublicKey->Encrypt(IntPtr::Zero, data, 0); 
		}
		// ����������� ������
		public: virtual array<BYTE>^ Encrypt(IPublicKey^ publicKey, IRand^ rand, array<BYTE>^ data) override; 
	};
	public ref class NDecipherment abstract : CAPI::Decipherment
	{
		// ������������ ������
		protected: array<BYTE>^ Decrypt(SecurityObject^ scope, 
			NKeyHandle^ hPrivateKey, IntPtr padding, array<BYTE>^ data, DWORD flags
		);
		// ������������ ������
		protected: virtual array<BYTE>^ Decrypt(
			SecurityObject^ scope, NKeyHandle^ hPrivateKey, array<BYTE>^ data)
		{
			// ������������ ������
			return Decrypt(scope, hPrivateKey, IntPtr::Zero, data, 0); 
		}
		// ������������ ������
		public: virtual array<BYTE>^ Decrypt(IPrivateKey^ privateKey, array<BYTE>^ data) override; 
	};
}}}
