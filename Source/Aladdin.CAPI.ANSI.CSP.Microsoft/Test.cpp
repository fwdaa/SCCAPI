#include "stdafx.h"
#include "Provider.h"
#include "RSA\RSABaseProvider.h"
#include "RSA\RSAEnhancedProvider.h"
#include "RSA\RSAStrongProvider.h"
#include "RSA\AESEnhancedProvider.h"
#include "RSA\RSASCardProvider.h"
#include "DSS\DSSBaseProvider.h"
#include "DSS\DSSEnhancedProvider.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft
{
	public ref class Test abstract sealed
	{
		public: static void Entry()
		{
			// �������� ���������� ����
			IWin32Window^ window = Aladdin::GUI::Win32Window::FromHandle(IntPtr(GetConsoleWindow())); 

			// ������� ��� ����������
			SecurityInfo^ infoHKLM = gcnew SecurityInfo(Scope::System, "HKLM\\CAPI-TEST"); 
			SecurityInfo^ infoHKCU = gcnew SecurityInfo(Scope::User  , "HKCU\\CAPI-TEST"); 

			// ������� ���������
			Using<Provider^> providerBaseRSA(gcnew RSA::BaseProvider()); 
			{ 
				Provider^ provider = providerBaseRSA.Get();  

				// ����������� ����������
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// ������� ������ ������ RSA � �����
				array<int>^ rsaBits = gcnew array<int> { 384, 512, 1024 }; 
            
				// ��������� ����
				ANSI::Test::TestMD2		      (provider, nullptr);
				ANSI::Test::TestMD4		      (provider, nullptr);
				ANSI::Test::TestMD5		      (provider, nullptr);
				ANSI::Test::TestSHA1	      (provider, nullptr);
				ANSI::Test::TestHMAC_MD5      (provider, nullptr); 
				ANSI::Test::TestHMAC_SHA1     (provider, nullptr); 
				ANSI::Test::TestRC2		      (provider, nullptr); 
				ANSI::Test::TestRC4		      (provider, nullptr); 
				ANSI::Test::TestDES		      (provider, nullptr); 
				ANSI::Test::TestTDES	      (provider, nullptr); 
				ANSI::Test::TestWrapRC2       (provider, nullptr); 
				ANSI::Test::TestWrapSMIME_DES (provider, nullptr);
				ANSI::Test::TestWrapSMIME_TDES(provider, nullptr);

				// ������� ���������
				CAPI::Container^ containerHKLM = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKLM);
				try {
					// ������� ��������� ��������� ������
					Using<IRand^> rand(provider->CreateRand(containerHKLM, window)); 

					// ��� ���� �������� ������
					for (int i = 0; i < rsaBits->Length; i++)
					{
						// ��������� ������������
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::None,       rsaBits[i], KeySizes::Range(5, 8)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::Exportable, rsaBits[i], KeySizes::Range(5, 8)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), false, KeyFlags::None,       rsaBits[i], KeySizes::Range(5, 8)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), false, KeyFlags::Exportable, rsaBits[i], KeySizes::Range(5, 8)); 
					}
				}
				// ������� ���������
				finally { containerHKLM->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKLM); }

				// ������� ���������
				CAPI::Container^ containerHKCU = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKCU);
				try {
					// ������� ��������� ��������� ������
					Using<IRand^> rand(provider->CreateRand(containerHKCU, window)); 

					// ��� ���� �������� ������
					for (int i = 0; i < rsaBits->Length; i++)
					{
						// ��������� ������������
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::None,       rsaBits[i], KeySizes::Range(5, 8)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::Exportable, rsaBits[i], KeySizes::Range(5, 8)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), false, KeyFlags::None,       rsaBits[i], KeySizes::Range(5, 8)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), false, KeyFlags::Exportable, rsaBits[i], KeySizes::Range(5, 8)); 
					}
				}
				// ������� ���������
				finally { containerHKCU->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKCU); }
			}
			// ������� ���������
			Using<Provider^> providerEnhancedRSA(gcnew RSA::EnhancedProvider()); 
			{ 
				Provider^ provider = providerEnhancedRSA.Get();  

				// ����������� ����������
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// ������� ������ ������ RSA � �����
				array<int>^ rsaBits = gcnew array<int> { 384, 512, 1024, 1536, 2048 }; 
            
				// ��������� ����
				ANSI::Test::TestMD2				(provider, nullptr);
				ANSI::Test::TestMD4				(provider, nullptr);
				ANSI::Test::TestMD5				(provider, nullptr);
				ANSI::Test::TestSHA1			(provider, nullptr);
				ANSI::Test::TestHMAC_MD5		(provider, nullptr); 
				ANSI::Test::TestHMAC_SHA1		(provider, nullptr); 
				ANSI::Test::TestRC2				(provider, nullptr); 
				ANSI::Test::TestRC4				(provider, nullptr); 
				ANSI::Test::TestDES				(provider, nullptr); 
				ANSI::Test::TestTDES			(provider, nullptr); 
				ANSI::Test::TestWrapRC2			(provider, nullptr); 
				ANSI::Test::TestWrapSMIME_DES	(provider, nullptr);
				ANSI::Test::TestWrapSMIME_TDES	(provider, nullptr);
				ANSI::Test::TestWrapTDES		(provider, nullptr); 

				// ������� ���������
				CAPI::Container^ containerHKLM = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKLM);
				try {
					// ������� ��������� ��������� ������
					Using<IRand^> rand(provider->CreateRand(containerHKLM, window)); 

					// ��� ���� �������� ������
					for (int i = 0; i < rsaBits->Length; i++)
					{
						// ��������� ������������
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::None,       rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::Exportable, rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), false, KeyFlags::None,       rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), false, KeyFlags::Exportable, rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::None,       rsaBits[i], KeySizes::Range(16, 24, 8)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::Exportable, rsaBits[i], KeySizes::Range(16, 24, 8)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), false, KeyFlags::None,       rsaBits[i], KeySizes::Range(16, 24, 8)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), false, KeyFlags::Exportable, rsaBits[i], KeySizes::Range(16, 24, 8)); 
					}
				}
				// ������� ���������
				finally { containerHKLM->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKLM); }

				// ������� ���������
				CAPI::Container^ containerHKCU = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKCU);
				try {
					// ������� ��������� ��������� ������
					Using<IRand^> rand(provider->CreateRand(containerHKCU, window)); 

					// ��� ���� �������� ������
					for (int i = 0; i < rsaBits->Length; i++)
					{
						// ��������� ������������
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::None,       rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::Exportable, rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), false, KeyFlags::None,       rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), false, KeyFlags::Exportable, rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::None,       rsaBits[i], KeySizes::Range(16, 24, 8)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::Exportable, rsaBits[i], KeySizes::Range(16, 24, 8)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), false, KeyFlags::None,       rsaBits[i], KeySizes::Range(16, 24, 8)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), false, KeyFlags::Exportable, rsaBits[i], KeySizes::Range(16, 24, 8)); 
					}
				}
				// ������� ���������
				finally { containerHKCU->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKCU); }
			}
			// ������� ���������
			Using<Provider^> providerStrongRSA(gcnew RSA::StrongProvider()); 
			{ 
				Provider^ provider = providerStrongRSA.Get();  

				// ����������� ����������
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// ������� ������ ������ RSA � �����
				array<int>^ rsaBits = gcnew array<int> { 384, 512, 1024, 1536, 2048 }; 

				// ��������� ����
				ANSI::Test::TestMD2				(provider, nullptr);
				ANSI::Test::TestMD4				(provider, nullptr);
				ANSI::Test::TestMD5				(provider, nullptr);
				ANSI::Test::TestSHA1			(provider, nullptr);
				ANSI::Test::TestHMAC_MD5		(provider, nullptr); 
				ANSI::Test::TestHMAC_SHA1		(provider, nullptr); 
				ANSI::Test::TestRC2				(provider, nullptr); 
				ANSI::Test::TestRC4				(provider, nullptr); 
				ANSI::Test::TestDES				(provider, nullptr); 
				ANSI::Test::TestTDES			(provider, nullptr); 
				ANSI::Test::TestWrapRC2			(provider, nullptr); 
				ANSI::Test::TestWrapSMIME_DES	(provider, nullptr);
				ANSI::Test::TestWrapSMIME_TDES	(provider, nullptr);
				ANSI::Test::TestWrapTDES		(provider, nullptr); 

				// ������� ���������
				CAPI::Container^ containerHKLM = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKLM);
				try {
					// ������� ��������� ��������� ������
					Using<IRand^> rand(provider->CreateRand(containerHKLM, window)); 

					// ��� ���� �������� ������
					for (int i = 0; i < rsaBits->Length; i++)
					{
						// ��������� ������������
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::None,       rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::Exportable, rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), false, KeyFlags::None,       rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), false, KeyFlags::Exportable, rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::None,       rsaBits[i], KeySizes::Range(16, 24, 8)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::Exportable, rsaBits[i], KeySizes::Range(16, 24, 8)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), false, KeyFlags::None,       rsaBits[i], KeySizes::Range(16, 24, 8)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), false, KeyFlags::Exportable, rsaBits[i], KeySizes::Range(16, 24, 8)); 
					}
				}
				// ������� ���������
				finally { containerHKLM->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKLM); }

				// ������� ���������
				CAPI::Container^ containerHKCU = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKCU);
				try {
					// ������� ��������� ��������� ������
					Using<IRand^> rand(provider->CreateRand(containerHKCU, window)); 

					// ��� ���� �������� ������
					for (int i = 0; i < rsaBits->Length; i++)
					{
						// ��������� ������������
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::None,       rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::Exportable, rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), false, KeyFlags::None,       rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), false, KeyFlags::Exportable, rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::None,       rsaBits[i], KeySizes::Range(16, 24, 8)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::Exportable, rsaBits[i], KeySizes::Range(16, 24, 8)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), false, KeyFlags::None,       rsaBits[i], KeySizes::Range(16, 24, 8)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), false, KeyFlags::Exportable, rsaBits[i], KeySizes::Range(16, 24, 8)); 
					}
				}
				// ������� ���������
				finally { containerHKCU->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKCU); }
			}
			// ������� ���������
			Using<Provider^> providerEnhancedAES(gcnew RSA::AESEnhancedProvider()); 
			{ 
				Provider^ provider = providerEnhancedAES.Get();  

				// ����������� ����������
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// ������� ������ ������ RSA � �����
				array<int>^ rsaBits = gcnew array<int> { 384, 512, 1024, 1536, 2048 }; 

				// ��������� ����
				ANSI::Test::TestMD2				(provider, nullptr);
				ANSI::Test::TestMD4				(provider, nullptr);
				ANSI::Test::TestMD5				(provider, nullptr);
				ANSI::Test::TestSHA1			(provider, nullptr);
				ANSI::Test::TestHMAC_MD5		(provider, nullptr); 
				ANSI::Test::TestHMAC_SHA1		(provider, nullptr); 
				ANSI::Test::TestRC2				(provider, nullptr); 
				ANSI::Test::TestRC4				(provider, nullptr); 
				ANSI::Test::TestDES				(provider, nullptr); 
				ANSI::Test::TestTDES			(provider, nullptr); 
				ANSI::Test::TestAES				(provider, nullptr); 
				ANSI::Test::TestWrapRC2			(provider, nullptr); 
				ANSI::Test::TestWrapSMIME_DES	(provider, nullptr);
				ANSI::Test::TestWrapSMIME_TDES	(provider, nullptr);
				ANSI::Test::TestWrapTDES		(provider, nullptr); 
				ANSI::Test::TestWrapAES			(provider, nullptr); 

				// ��������� ������ Windows
				if (IsWindows(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 3)) 
				{
					ANSI::Test::TestSHA2_256(provider, nullptr);
					ANSI::Test::TestSHA2_384(provider, nullptr);
					ANSI::Test::TestSHA2_512(provider, nullptr);

					ANSI::Test::TestHMAC_SHA2_256(provider, nullptr); 
					ANSI::Test::TestHMAC_SHA2_384(provider, nullptr); 
					ANSI::Test::TestHMAC_SHA2_512(provider, nullptr); 
				}
				// ������� ���������
				CAPI::Container^ containerHKLM = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKLM);
				try {
					// ������� ��������� ��������� ������
					Using<IRand^> rand(provider->CreateRand(containerHKLM, window)); 

					// ��� ���� �������� ������
					for (int i = 0; i < rsaBits->Length; i++)
					{
						// ��������� ������������
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::None,       rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::Exportable, rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), false, KeyFlags::None,       rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), false, KeyFlags::Exportable, rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::None,       rsaBits[i], KeySizes::Range(16, 32, 8)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::Exportable, rsaBits[i], KeySizes::Range(16, 32, 8)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), false, KeyFlags::None,       rsaBits[i], KeySizes::Range(16, 32, 8)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), false, KeyFlags::Exportable, rsaBits[i], KeySizes::Range(16, 32, 8)); 
					}
				}
				// ������� ���������
				finally { containerHKLM->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKLM); }

				// ������� ���������
				CAPI::Container^ containerHKCU = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKCU);
				try {
					// ������� ��������� ��������� ������
					Using<IRand^> rand(provider->CreateRand(containerHKCU, window)); 

					// ��� ���� �������� ������
					for (int i = 0; i < rsaBits->Length; i++)
					{
						// ��������� ������������
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::None,       rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::Exportable, rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), false, KeyFlags::None,       rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), false, KeyFlags::Exportable, rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::None,       rsaBits[i], KeySizes::Range(16, 32, 8)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::Exportable, rsaBits[i], KeySizes::Range(16, 32, 8)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), false, KeyFlags::None,       rsaBits[i], KeySizes::Range(16, 32, 8)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), false, KeyFlags::Exportable, rsaBits[i], KeySizes::Range(16, 32, 8)); 
					}
				}
				// ������� ���������
				finally { containerHKCU->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKCU); }
			}
			// ������� ���������
			Using<Provider^> providerBaseDSS(gcnew DSS::BaseProvider()); 
			{ 
				Provider^ provider = providerBaseDSS.Get();  

				// ����������� ����������
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// ��������� ����
	            ANSI::Test::TestMD5				(provider, nullptr);
				ANSI::Test::TestSHA1			(provider, nullptr);
				ANSI::Test::TestHMAC_MD5		(provider, nullptr); 
				ANSI::Test::TestHMAC_SHA1		(provider, nullptr); 
				ANSI::Test::TestRC2				(provider, nullptr); 
				ANSI::Test::TestRC4				(provider, nullptr); 
				ANSI::Test::TestDES				(provider, nullptr); 
				ANSI::Test::TestTDES			(provider, nullptr); 
				ANSI::Test::TestWrapRC2			(provider, nullptr); 
				ANSI::Test::TestWrapSMIME_DES	(provider, nullptr);
				ANSI::Test::TestWrapSMIME_TDES	(provider, nullptr);

				// ������� ���������
				CAPI::Container^ containerHKLM = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKLM);
				try {
					// ������� ��������� ��������� ������
					Using<IRand^> rand(provider->CreateRand(containerHKLM, window)); 

					// ��������� ������������
					ANSI::Test::TestDSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::None      ); 
					ANSI::Test::TestDSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::Exportable); 
					ANSI::Test::TestDSA(provider, containerHKLM, rand.Get(), false, KeyFlags::None      ); 
					ANSI::Test::TestDSA(provider, containerHKLM, rand.Get(), false, KeyFlags::Exportable); 
					ANSI::Test::TestDH (provider, containerHKLM, rand.Get(), true,  KeyFlags::None      ); 
					ANSI::Test::TestDH (provider, containerHKLM, rand.Get(), true,  KeyFlags::Exportable); 
					ANSI::Test::TestDH (provider, containerHKLM, rand.Get(), false, KeyFlags::None      ); 
					ANSI::Test::TestDH (provider, containerHKLM, rand.Get(), false, KeyFlags::Exportable); 
				}
				// ������� ���������
				finally { containerHKLM->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKLM); }

				// ������� ���������
				CAPI::Container^ containerHKCU = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKCU);
				try {
					// ������� ��������� ��������� ������
					Using<IRand^> rand(provider->CreateRand(containerHKCU, window)); 

					// ��������� ������������
					ANSI::Test::TestDSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::None      ); 
					ANSI::Test::TestDSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::Exportable); 
					ANSI::Test::TestDSA(provider, containerHKCU, rand.Get(), false, KeyFlags::None      ); 
					ANSI::Test::TestDSA(provider, containerHKCU, rand.Get(), false, KeyFlags::Exportable); 
					ANSI::Test::TestDH (provider, containerHKCU, rand.Get(), true,  KeyFlags::None      ); 
					ANSI::Test::TestDH (provider, containerHKCU, rand.Get(), true,  KeyFlags::Exportable); 
					ANSI::Test::TestDH (provider, containerHKCU, rand.Get(), false, KeyFlags::None      ); 
					ANSI::Test::TestDH (provider, containerHKCU, rand.Get(), false, KeyFlags::Exportable); 
				}
				// ������� ���������
				finally { containerHKCU->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKCU); }
			}
			// ������� ���������
			Using<Provider^> providerEnhancedDSS(gcnew DSS::EnhancedProvider()); 
			{ 
				Provider^ provider = providerEnhancedDSS.Get();  

				// ����������� ����������
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// ��������� ����
				ANSI::Test::TestMD5				(provider, nullptr);
				ANSI::Test::TestSHA1			(provider, nullptr);
				ANSI::Test::TestHMAC_MD5		(provider, nullptr); 
				ANSI::Test::TestHMAC_SHA1		(provider, nullptr); 
				ANSI::Test::TestRC2				(provider, nullptr); 
				ANSI::Test::TestRC4				(provider, nullptr); 
				ANSI::Test::TestDES				(provider, nullptr); 
				ANSI::Test::TestTDES			(provider, nullptr); 
				ANSI::Test::TestWrapRC2			(provider, nullptr); 
				ANSI::Test::TestWrapSMIME_DES	(provider, nullptr);
				ANSI::Test::TestWrapSMIME_TDES	(provider, nullptr);
				ANSI::Test::TestWrapTDES		(provider, nullptr); 

				// ������� ���������
				CAPI::Container^ containerHKLM = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKLM);
				try {
					// ������� ��������� ��������� ������
					Using<IRand^> rand(provider->CreateRand(containerHKLM, window)); 

					// ��������� ������������
					ANSI::Test::TestDSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::None      ); 
					ANSI::Test::TestDSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::Exportable); 
					ANSI::Test::TestDSA(provider, containerHKLM, rand.Get(), false, KeyFlags::None      ); 
					ANSI::Test::TestDSA(provider, containerHKLM, rand.Get(), false, KeyFlags::Exportable); 
					ANSI::Test::TestDH (provider, containerHKLM, rand.Get(), true,  KeyFlags::None      ); 
					ANSI::Test::TestDH (provider, containerHKLM, rand.Get(), true,  KeyFlags::Exportable); 
					ANSI::Test::TestDH (provider, containerHKLM, rand.Get(), false, KeyFlags::None      ); 
					ANSI::Test::TestDH (provider, containerHKLM, rand.Get(), false, KeyFlags::Exportable); 
				}
				// ������� ���������
				finally { containerHKLM->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKLM); }

				// ������� ���������
				CAPI::Container^ containerHKCU = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKCU);
				try {
					// ������� ��������� ��������� ������
					Using<IRand^> rand(provider->CreateRand(containerHKCU, window)); 

					// ��������� ������������
					ANSI::Test::TestDSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::None      ); 
					ANSI::Test::TestDSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::Exportable); 
					ANSI::Test::TestDSA(provider, containerHKCU, rand.Get(), false, KeyFlags::None      ); 
					ANSI::Test::TestDSA(provider, containerHKCU, rand.Get(), false, KeyFlags::Exportable); 
					ANSI::Test::TestDH (provider, containerHKCU, rand.Get(), true,  KeyFlags::None      ); 
					ANSI::Test::TestDH (provider, containerHKCU, rand.Get(), true,  KeyFlags::Exportable); 
					ANSI::Test::TestDH (provider, containerHKCU, rand.Get(), false, KeyFlags::None      ); 
					ANSI::Test::TestDH (provider, containerHKCU, rand.Get(), false, KeyFlags::Exportable); 
				}
				// ������� ���������
				finally { containerHKCU->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKCU); }
			}
			// ������� ���������
			Using<Provider^> providerSCardRSA(gcnew RSA::SCardProvider()); 
			{ 
				Provider^ provider = providerSCardRSA.Get();  

				// ����������� ����������
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// ������� ��� ����������
				SecurityInfo^ infoCard = gcnew SecurityInfo(Scope::System, "Card\\ARDS JaCarta 0\\CAPI-TEST"); 

				// ������� ������ ������ RSA � �����
				array<int>^ rsaBits = gcnew array<int> { 512, 1024, 1536, 2048 }; 

				// ��������� ����
				ANSI::Test::TestMD2				(provider, nullptr);
				ANSI::Test::TestMD4				(provider, nullptr);
				ANSI::Test::TestMD5				(provider, nullptr);
				ANSI::Test::TestSHA1			(provider, nullptr);
				ANSI::Test::TestHMAC_MD5		(provider, nullptr); 
				ANSI::Test::TestHMAC_SHA1		(provider, nullptr); 
				ANSI::Test::TestRC2				(provider, nullptr); 
				ANSI::Test::TestRC4				(provider, nullptr); 
				ANSI::Test::TestDES				(provider, nullptr); 
				ANSI::Test::TestTDES			(provider, nullptr); 
				ANSI::Test::TestAES				(provider, nullptr); 
				ANSI::Test::TestWrapRC2			(provider, nullptr); 
				ANSI::Test::TestWrapSMIME_DES	(provider, nullptr);
				ANSI::Test::TestWrapSMIME_TDES	(provider, nullptr);
				ANSI::Test::TestWrapTDES		(provider, nullptr); 
				ANSI::Test::TestWrapAES			(provider, nullptr); 

				// ��������� ������ Windows
				if (IsWindows(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 3)) 
				{
					ANSI::Test::TestSHA2_256(provider, nullptr);
					ANSI::Test::TestSHA2_384(provider, nullptr);
					ANSI::Test::TestSHA2_512(provider, nullptr);

					ANSI::Test::TestHMAC_SHA2_256(provider, nullptr); 
					ANSI::Test::TestHMAC_SHA2_384(provider, nullptr); 
					ANSI::Test::TestHMAC_SHA2_512(provider, nullptr); 
				}
				// ������� ���������
				CAPI::Container^ containerCard = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoCard);
				try {
					// ������� ��������� ��������� ������
					Using<IRand^> rand(provider->CreateRand(containerCard, window)); 

					// ��� ���� �������� ������
					for (int i = 0; i < rsaBits->Length; i++)
					{
						// ��������� ������������
						ANSI::Test::TestRSA(provider, containerCard, rand.Get(), true,  KeyFlags::None, rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerCard, rand.Get(), false, KeyFlags::None, rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerCard, rand.Get(), true,  KeyFlags::None, rsaBits[i], KeySizes::Range(16, 32, 8)); 
						ANSI::Test::TestRSA(provider, containerCard, rand.Get(), false, KeyFlags::None, rsaBits[i], KeySizes::Range(16, 32, 8)); 
					}
				}
				// ������� ���������
				finally { containerCard->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoCard); }
			}
		}
    };
}}}}}
