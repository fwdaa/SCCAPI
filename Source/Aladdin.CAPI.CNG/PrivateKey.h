#pragma once

#include "Handle.h"

namespace Aladdin { namespace CSP 
{
	ref class Container; 

	///////////////////////////////////////////////////////////////////////////
	// ������ ���� �������������� ���������
	///////////////////////////////////////////////////////////////////////////
	public ref class PrivateKey : CAPI::IPrivateKey
	{
		private: CAPI::IKeyFactory^	keyFactory;		// ������� ������
		private: CSP::Container^	container;		// ��������� �����
		private: CAPI::KeyUsage		keyUsage;		// ��� �����
 
		// �����������
		public: PrivateKey(CAPI::IKeyFactory^ keyFactory, CSP::Container^ container, 
			CAPI::KeyUsage keyUsage) 
		{
			this->keyFactory	= keyFactory;		// ������� ����������
			this->container		= container;		// ��������� �����
			this->keyUsage		= keyUsage;			// ��� �����
		}
		public: virtual ~PrivateKey() {}

		// ������� ����������
		public: virtual property CAPI::IKeyFactory^ KeyFactory 
		{ 
			// ������� ������� ����������
			CAPI::IKeyFactory^ get() { return keyFactory; }
		}
		// ��������� � ��� ����� 
		public: property CSP::Container^ Container { CSP::Container^ get() { return container; }} 
		public: property CAPI::KeyUsage  KeyUsage  { CAPI::KeyUsage  get() { return keyUsage;  }} 
	};
	///////////////////////////////////////////////////////////////////////////
	// ��������� ������ ���� �������������� ���������
	///////////////////////////////////////////////////////////////////////////
	public ref class EphemeralPrivateKey : CAPI::IPrivateKey
	{
		private: CAPI::IKeyFactory^	keyFactory;		// ������� ������
		private: KeyPtr				hPrivateKey;	// ��������� �����

		// ����������� 
		public: EphemeralPrivateKey(CAPI::IKeyFactory^ keyFactory, KeyPtr hKey) : hPrivateKey(hKey) 
		{ 
			this->keyFactory = keyFactory;		// ������� ����������
		}  
		// ������� ��������� ������� �����
		public: virtual ~EphemeralPrivateKey() { hPrivateKey.Clear(); }

		// ������� ����������
		public: virtual property CAPI::IKeyFactory^ KeyFactory 
		{ 
			// ������� ������� ��aQ��������
			CAPI::IKeyFactory^ get() { return keyFactory; }
		}
		// ��������� ������� �����
		public: property KeyPtr Handle { KeyPtr get() { return hPrivateKey; } } 
	};
}}