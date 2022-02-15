#include "stdafx.h"
#include "RSA\RSAProvider.h"
#include "GOST34310\GOST34310Provider.h"

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar
{
	public ref class Test abstract sealed
	{
		public: static void TestProviderRSA(CAPI::CSP::Provider^ provider)
        {
			ANSI::Test::TestSHA1(provider, nullptr);

			// ��������� ������ Windows
			if (IsWindows(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 3)) 
			{
				// � ������ ������ CSP ������ ��� ������ �� 55 ������
				ANSI::Test::TestSHA2_256(provider, nullptr);

				// � ������ ������ CSP ������ ��� ������ �� 111 ������
				ANSI::Test::TestSHA2_384(provider, nullptr);

				// � ������ ������ CSP ������ ��� ������ �� 111 ������
				ANSI::Test::TestSHA2_512(provider, nullptr);
			}
            ANSI::Test::TestHMAC_SHA1(provider, nullptr); 

			// ��������� ������ Windows
			if (IsWindows(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 3)) 
			{
				// � ������ ������ CSP ������ ��� ������ �� 55 ������
				ANSI::Test::TestHMAC_SHA2_256(provider, nullptr); 

				// � ������ ������ CSP ������ ��� ������ �� 111 ������
				ANSI::Test::TestHMAC_SHA2_384(provider, nullptr); 

				// � ������ ������ CSP ������ ��� ������ �� 111 ������
				ANSI::Test::TestHMAC_SHA2_512(provider, nullptr); 
			}
            ANSI::Test::TestRC2 (provider, nullptr); 
            ANSI::Test::TestRC4 (provider, nullptr); 
            ANSI::Test::TestDES (provider, nullptr); 
            ANSI::Test::TestTDES(provider, nullptr); 

			// ������ ��������� ������ ACCESS VIOLATION
            // ANSI::Test::TestAES (provider, nullptr); 
		}
		public: static void TestContainerRSA(IWin32Window^ window, CAPI::CSP::Provider^ provider, SecurityInfo^ info)
        {
			// ��� SHA2_384 � SHA2_512 ���������� ������������ �����
			array<String^>^ keyOIDs = gcnew array<String^> { 
				ASN1::KZ::OID::gamma_key_rsa_1024, ASN1::KZ::OID::gamma_key_rsa_1024_xch,
				ASN1::KZ::OID::gamma_key_rsa_1536, ASN1::KZ::OID::gamma_key_rsa_1536_xch,
				ASN1::KZ::OID::gamma_key_rsa_2048, ASN1::KZ::OID::gamma_key_rsa_2048_xch
			}; 
			// ������� ���������
			Using<CAPI::Container^> container(GUI::AuthenticationSelector::OpenOrCreate(window, provider, info));

			// ������� ��������� ��������� ������
			Using<IRand^> rand(provider->CreateRand(container.Get(), window)); 

			// ��� ���������� �������� 
			for (int i = 0; i < keyOIDs->Length; i++)
			{
				// ��������� ������������
				CAPI::KZ::Test::TestRSA(provider, container.Get(), rand.Get(), 
					true, KeyFlags::None, keyOIDs[i], gcnew array<int>(0)
				); 
			}
		}
		public: static void TestProviderGOST(CAPI::CSP::Provider^ provider)
        {
            GOST::Test::TestGOSTR3411_1994(provider, nullptr, ASN1::GOST::OID::hashes_test     ); 
            GOST::Test::TestGOSTR3411_1994(provider, nullptr, ASN1::GOST::OID::hashes_cryptopro); 
            KZ  ::Test::TestGOST34311_1994(provider, nullptr); 
            KZ  ::Test::TestGOST28147     (provider, nullptr); 
		}
		public: static void TestContainerGOST(IWin32Window^ window, CAPI::CSP::Provider^ provider, SecurityInfo^ info)
        {
			// ������ ��������� ������ "Keyset does not exist"

			// ������� ���������
			Using<CAPI::Container^> container(GUI::AuthenticationSelector::OpenOrCreate(window, provider, info));

			// ������� ��������� ��������� ������
			Using<IRand^> rand(provider->CreateRand(container.Get(), window)); 

            KZ::Test::TestGOST34310(
				provider, container.Get(), rand.Get(), true, KeyFlags::None, 
				ASN1::KZ::OID::gamma_key_ec256_512_a
            ); 
            KZ::Test::TestGOST34310(
				provider, container.Get(), rand.Get(), true, KeyFlags::None, 
				ASN1::KZ::OID::gamma_key_ec256_512_b
            ); 
            KZ::Test::TestGOST34310(
				provider, container.Get(), rand.Get(), true, KeyFlags::None, 
				ASN1::KZ::OID::gamma_key_ec256_512_c
            ); 
            KZ::Test::TestGOST34310(
				provider, container.Get(), rand.Get(), true, KeyFlags::None, 
				ASN1::KZ::OID::gamma_key_ec256_512_a_xch 
            ); 
		}
		public: static void Entry()
		{
			// ������� ������������ ���� 
			IWin32Window^ window = Aladdin::GUI::Win32Window::FromHandle(IntPtr(GetConsoleWindow())); 

			// ������� ��� ����������
			SecurityInfo^ info = gcnew SecurityInfo(
				Scope::System, "Card\\Athena ASEDrive V3C 0"
			); 
			// ������� ���������
			Using<CAPI::CSP::Provider^> providerRSA(gcnew RSA::Provider()); 
			{ 
				CAPI::CSP::Provider^ provider = providerRSA.Get(); 

				// ����������� ����������
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// ��������� �����
				TestProviderRSA  (        providerRSA.Get()); 
				TestContainerRSA (window, providerRSA.Get(), info); 

				// ��������� �����
				TestProviderGOST (        providerRSA.Get()); 
				TestContainerGOST(window, providerRSA.Get(), info); 
			}
			// ������� ���������
			Using<CAPI::CSP::Provider^> providerGOST(gcnew GOST34310::Provider()); 
			{ 
				CAPI::CSP::Provider^ provider = providerGOST.Get(); 

				// ����������� ����������
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// ��������� �����
				TestProviderRSA  (        providerGOST.Get()); 
				TestContainerRSA (window, providerGOST.Get(), info); 

				// ��������� �����
				TestProviderGOST (        providerGOST.Get()); 
				TestContainerGOST(window, providerGOST.Get(), info); 
			}
		}
    };
}}}}}
