#pragma once

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro 
{
	///////////////////////////////////////////////////////////////////////////
	// ������ ��������� ��������������
	///////////////////////////////////////////////////////////////////////////
	public ref class PasswordService : CAPI::CSP::PasswordService
	{
		// �����������
		public: PasswordService(SecurityObject^ obj, CAPI::CSP::Handle^ handle, bool canChange) 
			: CAPI::CSP::PasswordService(obj, handle) 
		
			// ��������� ���������� ���������
			{ this->canChange = canChange; } private: bool canChange; 
        
        // ����������� ��������� 
		public: virtual property bool CanChange { bool get() override { return canChange; }}

		// ������� ������������������ ������
		protected: virtual void SetPassword(String^ password) override; 
		// �������� ������������������ ������
		protected: virtual void ChangePassword(String^ password) override; 
	}; 
}}}}}
