#include "stdafx.h"
#include "Provider.h"
#include "PrimitiveProvider.h"
#include "SoftwareProvider.h"
#include "SCardProvider.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft
{
	public ref class Test abstract sealed
	{
		public: static void TestAllKeys(CAPI::Factory^ factory, SecurityObject^ scope, IRand^ rand)
        {
			// ������� ������ ������ RSA � �����
			array<int>^ rsaBits = gcnew array<int> { 512, 1024, 1536, 2048 }; 

			// ��� ���� �������� ������
			for (int i = 0; i < rsaBits->Length; i++)
			{
				// ��������� ������������
				ANSI::Test::TestRSA(factory, scope, rand, true,  KeyFlags::None,       rsaBits[i], KeySizes::Range(1, 16)); 
				ANSI::Test::TestRSA(factory, scope, rand, true,  KeyFlags::Exportable, rsaBits[i], KeySizes::Range(1, 16)); 
				ANSI::Test::TestRSA(factory, scope, rand, false, KeyFlags::None,       rsaBits[i], KeySizes::Range(1, 16)); 
				ANSI::Test::TestRSA(factory, scope, rand, false, KeyFlags::Exportable, rsaBits[i], KeySizes::Range(1, 16)); 

				// ��������� ������������
				ANSI::Test::TestRSA(factory, scope, rand, true,  KeyFlags::None,       rsaBits[i], KeySizes::Range(16, 32, 8)); 
				ANSI::Test::TestRSA(factory, scope, rand, true,  KeyFlags::Exportable, rsaBits[i], KeySizes::Range(16, 32, 8)); 
				ANSI::Test::TestRSA(factory, scope, rand, false, KeyFlags::None,       rsaBits[i], KeySizes::Range(16, 32, 8)); 
				ANSI::Test::TestRSA(factory, scope, rand, false, KeyFlags::Exportable, rsaBits[i], KeySizes::Range(16, 32, 8)); 
			}
			// ��������� ������������
			ANSI::Test::TestDSA(factory, scope, rand, true,  KeyFlags::None      ); 
			ANSI::Test::TestDSA(factory, scope, rand, true,  KeyFlags::Exportable); 
			ANSI::Test::TestDSA(factory, scope, rand, false, KeyFlags::None      ); 
			ANSI::Test::TestDSA(factory, scope, rand, false, KeyFlags::Exportable); 
			ANSI::Test::TestDH (factory, scope, rand, true,  KeyFlags::None      ); 
			ANSI::Test::TestDH (factory, scope, rand, true,  KeyFlags::Exportable); 
			ANSI::Test::TestDH (factory, scope, rand, false, KeyFlags::None      ); 
			ANSI::Test::TestDH (factory, scope, rand, false, KeyFlags::Exportable); 

			// ������� �������������� ����������
			array<String^>^ ecOIDs = gcnew array<String^> {
				ASN1::ANSI::OID::x962_curves_prime256v1,
				ASN1::ANSI::OID::certicom_curves_secp384r1, 
				ASN1::ANSI::OID::certicom_curves_secp521r1
			}; 
			// ��� ���� ������� ����������
			for (int i = 0; i < ecOIDs->Length; i++)
			{
				// ��������� ������������
				ANSI::Test::TestEC(factory, scope, rand, true,  KeyFlags::None,       ecOIDs[i]); 
				ANSI::Test::TestEC(factory, scope, rand, true,  KeyFlags::Exportable, ecOIDs[i]); 
				ANSI::Test::TestEC(factory, scope, rand, false, KeyFlags::None,       ecOIDs[i]); 
				ANSI::Test::TestEC(factory, scope, rand, false, KeyFlags::Exportable, ecOIDs[i]); 
			}
		}
		public: static void Entry()
		{
			// �������� ���������� ����
			IWin32Window^ window = Aladdin::GUI::Win32Window::FromHandle(IntPtr(GetConsoleWindow())); 

			// ������� ������� ����������
			Using<PrimitiveProvider^> factory(gcnew PrimitiveProvider()); 
			{
				ANSI::Test::TestMD2			 (factory.Get(), nullptr);
				ANSI::Test::TestMD4			 (factory.Get(), nullptr);
				ANSI::Test::TestMD5			 (factory.Get(), nullptr);
				ANSI::Test::TestSHA1		 (factory.Get(), nullptr);
				ANSI::Test::TestSHA2_256	 (factory.Get(), nullptr);
				ANSI::Test::TestSHA2_384	 (factory.Get(), nullptr);
				ANSI::Test::TestSHA2_512	 (factory.Get(), nullptr);
				ANSI::Test::TestHMAC_MD5	 (factory.Get(), nullptr); 
				ANSI::Test::TestHMAC_SHA1	 (factory.Get(), nullptr); 
				ANSI::Test::TestHMAC_SHA2_256(factory.Get(), nullptr); 
				ANSI::Test::TestHMAC_SHA2_384(factory.Get(), nullptr); 
				ANSI::Test::TestHMAC_SHA2_512(factory.Get(), nullptr); 
				ANSI::Test::TestRC2			 (factory.Get(), nullptr); 
				ANSI::Test::TestRC4			 (factory.Get(), nullptr); 
				ANSI::Test::TestDES			 (factory.Get(), nullptr); 
				ANSI::Test::TestTDES	 	 (factory.Get(), nullptr); 
				ANSI::Test::TestAES			 (factory.Get(), nullptr); 

				// ������� ��������� ��������� ������
				Using<IRand^> rand(factory.Get()->CreateRand(window)); 

				// ��������� ������������
				TestAllKeys(factory.Get(), nullptr, rand.Get()); 		
			}
			// ������� ���������
			Using<Provider^> providerSoftware(gcnew SoftwareProvider()); 
			{ 
				Provider^ provider = providerSoftware.Get(); 

				// ������� ����� �����������
				SecurityInfo^ infoHKLM = gcnew SecurityInfo(Scope::System, "HKLM\\CAPI-TEST"); 
				SecurityInfo^ infoHKCU = gcnew SecurityInfo(Scope::User  , "HKCU\\CAPI-TEST"); 

				// ����������� ����������
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// ������� ���������
				CAPI::Container^ containerHKLM = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKLM);
				try {
					// ������� ����� ����������
					containerHKLM->DeleteKeys();

					// ������� ��������� ��������� ������
					Using<IRand^> rand(provider->CreateRand(containerHKLM, window)); 

					// ��������� �����
					TestAllKeys(provider, containerHKLM, rand.Get()); 		
				}
				// ������� ���������
				finally { containerHKLM->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKLM); }

				// ������� ���������
				CAPI::Container^ containerHKCU = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKLM);
				try {
					// ������� ����� ����������
					containerHKCU->DeleteKeys();

					// ������� ��������� ��������� ������
					Using<IRand^> rand(provider->CreateRand(containerHKCU, window)); 

					// ��������� �����
					TestAllKeys(provider, containerHKCU, rand.Get()); 		
				}
				// ������� ���������
				finally { containerHKCU->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKCU); }
			}
			// ������� ���������
			Using<Provider^> providerSCard(gcnew SCardProvider()); 
			{ 
				Provider^ provider = providerSCard.Get(); 

				// ����������� ����������
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// ������� ��� ����������
				SecurityInfo^ infoCard = gcnew SecurityInfo(
					Scope::System, "Card\\ARDS JaCarta 0\\CAPI-TEST"
				); 
				// ������� ���������
				CAPI::Container^ containerCard = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoCard);
				try {
					// ������� ����� ����������
					containerCard->DeleteKeys(); 

					// ������� ��������� ��������� ������
					Using<IRand^> rand(provider->CreateRand(containerCard, window)); 

					// ��������� ������������
					ANSI::Test::TestRSA(provider, containerCard, rand.Get(), true,  KeyFlags::None, 512, KeySizes::Range(1, 16    )); 
					ANSI::Test::TestRSA(provider, containerCard, rand.Get(), true,  KeyFlags::None, 512, KeySizes::Range(16, 32, 8)); 
				}
				// ������� ���������
				finally { containerCard->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoCard); }
			}
		}
    };
}}}}}
