#pragma once

#include "Container.h"

using namespace System::Collections::Generic; 

namespace Aladdin { namespace CAPI { namespace CNG 
{
	ref class PasswordProvider; 

	///////////////////////////////////////////////////////////////////////////
	// ��� �������
	///////////////////////////////////////////////////////////////////////////
	public interface class IPasswordCache
	{
		// �������� ������ � ���
		public: virtual void SetPassword(String^ container, String^ password) = 0; 

		// ������ ��������� ������� �� ����
		public: virtual array<String^>^ GetPasswords(String^ container) = 0; 
	}; 
	///////////////////////////////////////////////////////////////////////////
	// ���������������� ��� �������
	///////////////////////////////////////////////////////////////////////////
	public ref class NoPasswordCache : IPasswordCache
	{
		// �������� ������ � ���
		public: virtual void SetPassword(String^ container, String^ password) {} 

		// ������ ��������� ������� �� ����
		public: virtual array<String^>^ GetPasswords(String^ container) 
		{
			// ��� ������� �� ��������������
			return gcnew array<String^>(0); 
		}
	}; 
	///////////////////////////////////////////////////////////////////////////
	// ��� ������� �� ��������� �����������
	///////////////////////////////////////////////////////////////////////////
	public ref class ContainerPasswordCache : IPasswordCache
	{
		// ������ �����������
		private: Dictionary<String^, List<String^>^>^ passwords;

		// �����������
		public: ContainerPasswordCache()
		{
			// ������� ������ ������ �������
			passwords = gcnew Dictionary<String^, List<String^>^>(); 
		}
		// �������� ������ � ���
		public: virtual void SetPassword(String^ container, String^ password); 

		// ������ ��������� ������� �� ����
		public: virtual array<String^>^ GetPasswords(String^ container);

		// �������� ��� ���������� ��� ����� �����������
		protected: virtual String^ GetContainerName(String^ container); 
	}; 
	///////////////////////////////////////////////////////////////////////////
	// ��������, ������������ ����� ��������������
	///////////////////////////////////////////////////////////////////////////
	public interface class IPasswordAction
	{
		// ��������� �������� ��� �������� ������
		public: virtual Object^ Invoke() = 0; 

		// ��������� �������� � ��������� ������
		public: virtual Object^ PasswordInvoke(String^ password) = 0; 
	}; 
	///////////////////////////////////////////////////////////////////////////
	// �������� ����������
	///////////////////////////////////////////////////////////////////////////
	public ref class CreateContainerAction : IPasswordAction
	{
		// ������������ ��������� � ��� ����������
		private: PasswordProvider^ provider; private: String^ container; 
	
		// ��� ����������, ����� �������� � ������� ��������� ������
		private: DWORD flags; private: PasswordCallback^ callback;

		// �����������
		public: CreateContainerAction(PasswordProvider^ provider, 
			String^ container, DWORD flags, PasswordCallback^ callback) 
		{
			// ��������� ���������� ���������
			this->provider = provider; this->container = container; 
			
			// ��������� ���������� ���������
			this->flags = flags; this->callback = callback; 
		}
		// ��������� �������� ��� �������� ������
		public: virtual Object^ Invoke(); 

		// ��������� �������� � ��������� ������
		public: virtual Object^ PasswordInvoke(String^ password); 
	}; 
	///////////////////////////////////////////////////////////////////////////
	// �������� ����������
	///////////////////////////////////////////////////////////////////////////
	public ref class DeleteContainerAction : IPasswordAction
	{
		// ��������� � ��� ����������
		private: PasswordProvider^ provider; private: String^ container; 

		// �����������
		public: DeleteContainerAction(PasswordProvider^ provider, String^ container) 
		{
			// ��������� ���������� ���������
			this->provider = provider; this->container = container; 
		}
		// ��������� �������� ��� �������� ������
		public: virtual Object^ Invoke(); 

		// ��������� �������� � ��������� ������
		public: virtual Object^ PasswordInvoke(String^ password); 
	};
	///////////////////////////////////////////////////////////////////////////
	// �������� � �����������, ������������ ����� ��������������
	///////////////////////////////////////////////////////////////////////////
	public ref class ContainerPasswordAction abstract : IPasswordAction
	{
		// ������������ ���������
		private: CSP::Container^ container;

		// �����������
		public: ContainerPasswordAction(CSP::Container^ container) 
		{
			// ��������� ������������ ���������
			this->container = container; 
		}
		// ������������ ���������
		public: property CSP::Container^ Container 
		{ 
			// ������������ ���������
			CSP::Container^ get() { return container; }
		}
		// ��������� �������� ��� �������� ������
		public: virtual Object^ Invoke() = 0; 

		// ��������� �������� � ��������� ������
		public: virtual Object^ PasswordInvoke(String^ password); 
	}; 
	/////////////////////////////////////////////////
	// ��������� �����������
	/////////////////////////////////////////////////
	private ref class SetCertificateAction : ContainerPasswordAction
	{
		// �������� ���� � ����������
		private: KeyHandle hPublicKey; private: Binary^ certificate;
				 
		// �����������
		public: SetCertificateAction(CSP::Container^ container, KeyHandle hPublicKey, 
			Binary^ certificate) : ContainerPasswordAction(container)
		{
			// ��������� ���������� ���������
			this->hPublicKey = hPublicKey; this->certificate = certificate;
		}
		// ������������� ���� ������
		public: virtual Object^ Invoke() override
		{
			// ���������� ����������
			hPublicKey->SetParam(KP_CERTIFICATE, certificate, 0); return nullptr; 
		}
	};
	/////////////////////////////////////////////////
	// ��������� ���� ������
	/////////////////////////////////////////////////
	private ref class GenerateKeyAction : ContainerPasswordAction
	{
		// ��� ����� � ����� ���������
		private: ALG_ID algID; private: DWORD flags;
				 
		// �����������
		public: GenerateKeyAction(CSP::Container^ container, ALG_ID algID, DWORD flags)
			: ContainerPasswordAction(container)
		{
			// ��������� ���������� ���������
			this->algID = algID; this->flags = flags;
		}
		// ������������� ���� ������
		public: virtual Object^ Invoke() override
		{
			// ������������� ���� ������
			return Container->Handle->Context.GenerateKey(algID, flags); 
		}
	};
	/////////////////////////////////////////////////
	// ������ �����
	/////////////////////////////////////////////////
	private ref class ImportKeyAction : ContainerPasswordAction
	{
		// ���� ��� ������� � ������������� ������
		private: KeyHandle hImportKey; private: Binary^ data; private: DWORD flags;

		// �����������
		public: ImportKeyAction(CSP::Container^ container, KeyHandle hImportKey, Binary^ data, DWORD flags)
			: ContainerPasswordAction(container)
		{
			// ��������� ���������� ���������
			this->hImportKey = hImportKey; this->data = data; this->flags = flags;
		}
		// ������������� ���� � ���������
		public: virtual Object^ Invoke() override
		{
			// ������������� ���� � ���������
			return Container->Handle->Context.ImportKey(hImportKey, data, flags); 
		}
	};
	/////////////////////////////////////////////////
	// ������������ ������
	/////////////////////////////////////////////////
	private ref class DecryptAction : ContainerPasswordAction
	{
		// ��������� ����� � ���������������� ������
		private: KeyHandle hKey; private: Binary^ data; private: DWORD flags;

		// �����������
		public: DecryptAction(CSP::Container^ container, KeyHandle hKey, Binary^ data, DWORD flags)
			: ContainerPasswordAction(container)
		{
			// ��������� ���������� ���������
			this->hKey = hKey; this->data = data; this->flags = flags;
		}
		// ������������ ������
		public: virtual Object^ Invoke() override { return hKey->Decrypt(data, flags); } 
	};
	/////////////////////////////////////////////////
	// ������� ���-��������
	/////////////////////////////////////////////////
	private ref class SignHashAction : ContainerPasswordAction
	{
		// ��� ����� � ��������� ��������� ����������� 
		private: DWORD keyType; private: HashHandle hHash; private: DWORD flags; 

		// �����������
		public: SignHashAction(CSP::Container^ container, DWORD keyType, HashHandle hHash, DWORD flags)
			: ContainerPasswordAction(container)
		{
			// ��������� ���������� ���������
			this->keyType = keyType; this->hHash = hHash; this->flags = flags; 
		}
		// ��������� ���-��������
		public: virtual Object^ Invoke() override
		{ 
			// ��������� ���-��������
			return Container->Handle->SignHash(keyType, hHash, flags); 
		} 
	};
}}}
