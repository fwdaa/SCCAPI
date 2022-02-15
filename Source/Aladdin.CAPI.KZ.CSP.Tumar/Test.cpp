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

			// проверить версию Windows
			if (IsWindows(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 3)) 
			{
				// в старой версии CSP ошибка для данных из 55 байтов
				ANSI::Test::TestSHA2_256(provider, nullptr);

				// в старой версии CSP ошибка для данных из 111 байтов
				ANSI::Test::TestSHA2_384(provider, nullptr);

				// в старой версии CSP ошибка для данных из 111 байтов
				ANSI::Test::TestSHA2_512(provider, nullptr);
			}
            ANSI::Test::TestHMAC_SHA1(provider, nullptr); 

			// проверить версию Windows
			if (IsWindows(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 3)) 
			{
				// в старой версии CSP ошибка для данных из 55 байтов
				ANSI::Test::TestHMAC_SHA2_256(provider, nullptr); 

				// в старой версии CSP ошибка для данных из 111 байтов
				ANSI::Test::TestHMAC_SHA2_384(provider, nullptr); 

				// в старой версии CSP ошибка для данных из 111 байтов
				ANSI::Test::TestHMAC_SHA2_512(provider, nullptr); 
			}
            ANSI::Test::TestRC2 (provider, nullptr); 
            ANSI::Test::TestRC4 (provider, nullptr); 
            ANSI::Test::TestDES (provider, nullptr); 
            ANSI::Test::TestTDES(provider, nullptr); 

			// иногда возникает ошибка ACCESS VIOLATION
            // ANSI::Test::TestAES (provider, nullptr); 
		}
		public: static void TestContainerRSA(IWin32Window^ window, CAPI::CSP::Provider^ provider, SecurityInfo^ info)
        {
			// для SHA2_384 и SHA2_512 происходит переполнение стека
			array<String^>^ keyOIDs = gcnew array<String^> { 
				ASN1::KZ::OID::gamma_key_rsa_1024, ASN1::KZ::OID::gamma_key_rsa_1024_xch,
				ASN1::KZ::OID::gamma_key_rsa_1536, ASN1::KZ::OID::gamma_key_rsa_1536_xch,
				ASN1::KZ::OID::gamma_key_rsa_2048, ASN1::KZ::OID::gamma_key_rsa_2048_xch
			}; 
			// создать контейнер
			Using<CAPI::Container^> container(GUI::AuthenticationSelector::OpenOrCreate(window, provider, info));

			// создать генератор случайных данных
			Using<IRand^> rand(provider->CreateRand(container.Get(), window)); 

			// для допустимых размеров 
			for (int i = 0; i < keyOIDs->Length; i++)
			{
				// выполнить тестирование
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
			// иногда возникает ошибка "Keyset does not exist"

			// создать контейнер
			Using<CAPI::Container^> container(GUI::AuthenticationSelector::OpenOrCreate(window, provider, info));

			// создать генератор случайных данных
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
			// указать используемое окно 
			IWin32Window^ window = Aladdin::GUI::Win32Window::FromHandle(IntPtr(GetConsoleWindow())); 

			// указать имя контейнера
			SecurityInfo^ info = gcnew SecurityInfo(
				Scope::System, "Card\\Athena ASEDrive V3C 0"
			); 
			// указать провайдер
			Using<CAPI::CSP::Provider^> providerRSA(gcnew RSA::Provider()); 
			{ 
				CAPI::CSP::Provider^ provider = providerRSA.Get(); 

				// перечислить контейнеры
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// выполнить тесты
				TestProviderRSA  (        providerRSA.Get()); 
				TestContainerRSA (window, providerRSA.Get(), info); 

				// выполнить тесты
				TestProviderGOST (        providerRSA.Get()); 
				TestContainerGOST(window, providerRSA.Get(), info); 
			}
			// указать провайдер
			Using<CAPI::CSP::Provider^> providerGOST(gcnew GOST34310::Provider()); 
			{ 
				CAPI::CSP::Provider^ provider = providerGOST.Get(); 

				// перечислить контейнеры
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// выполнить тесты
				TestProviderRSA  (        providerGOST.Get()); 
				TestContainerRSA (window, providerGOST.Get(), info); 

				// выполнить тесты
				TestProviderGOST (        providerGOST.Get()); 
				TestContainerGOST(window, providerGOST.Get(), info); 
			}
		}
    };
}}}}}
