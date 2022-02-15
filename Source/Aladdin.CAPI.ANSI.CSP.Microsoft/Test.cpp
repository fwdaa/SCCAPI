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
			// получить консольное окно
			IWin32Window^ window = Aladdin::GUI::Win32Window::FromHandle(IntPtr(GetConsoleWindow())); 

			// указать имя контейнера
			SecurityInfo^ infoHKLM = gcnew SecurityInfo(Scope::System, "HKLM\\CAPI-TEST"); 
			SecurityInfo^ infoHKCU = gcnew SecurityInfo(Scope::User  , "HKCU\\CAPI-TEST"); 

			// указать провайдер
			Using<Provider^> providerBaseRSA(gcnew RSA::BaseProvider()); 
			{ 
				Provider^ provider = providerBaseRSA.Get();  

				// перечислить контейнеры
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// указать размер ключей RSA в битах
				array<int>^ rsaBits = gcnew array<int> { 384, 512, 1024 }; 
            
				// выполнить тест
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

				// создать контейнер
				CAPI::Container^ containerHKLM = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKLM);
				try {
					// создать генератор случайных данных
					Using<IRand^> rand(provider->CreateRand(containerHKLM, window)); 

					// для всех размеров ключей
					for (int i = 0; i < rsaBits->Length; i++)
					{
						// выполнить тестирование
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::None,       rsaBits[i], KeySizes::Range(5, 8)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::Exportable, rsaBits[i], KeySizes::Range(5, 8)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), false, KeyFlags::None,       rsaBits[i], KeySizes::Range(5, 8)); 
						ANSI::Test::TestRSA(provider, containerHKLM, rand.Get(), false, KeyFlags::Exportable, rsaBits[i], KeySizes::Range(5, 8)); 
					}
				}
				// удалить контейнер
				finally { containerHKLM->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKLM); }

				// создать контейнер
				CAPI::Container^ containerHKCU = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKCU);
				try {
					// создать генератор случайных данных
					Using<IRand^> rand(provider->CreateRand(containerHKCU, window)); 

					// для всех размеров ключей
					for (int i = 0; i < rsaBits->Length; i++)
					{
						// выполнить тестирование
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::None,       rsaBits[i], KeySizes::Range(5, 8)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::Exportable, rsaBits[i], KeySizes::Range(5, 8)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), false, KeyFlags::None,       rsaBits[i], KeySizes::Range(5, 8)); 
						ANSI::Test::TestRSA(provider, containerHKCU, rand.Get(), false, KeyFlags::Exportable, rsaBits[i], KeySizes::Range(5, 8)); 
					}
				}
				// удалить контейнер
				finally { containerHKCU->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKCU); }
			}
			// указать провайдер
			Using<Provider^> providerEnhancedRSA(gcnew RSA::EnhancedProvider()); 
			{ 
				Provider^ provider = providerEnhancedRSA.Get();  

				// перечислить контейнеры
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// указать размер ключей RSA в битах
				array<int>^ rsaBits = gcnew array<int> { 384, 512, 1024, 1536, 2048 }; 
            
				// выполнить тест
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

				// создать контейнер
				CAPI::Container^ containerHKLM = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKLM);
				try {
					// создать генератор случайных данных
					Using<IRand^> rand(provider->CreateRand(containerHKLM, window)); 

					// для всех размеров ключей
					for (int i = 0; i < rsaBits->Length; i++)
					{
						// выполнить тестирование
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
				// удалить контейнер
				finally { containerHKLM->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKLM); }

				// создать контейнер
				CAPI::Container^ containerHKCU = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKCU);
				try {
					// создать генератор случайных данных
					Using<IRand^> rand(provider->CreateRand(containerHKCU, window)); 

					// для всех размеров ключей
					for (int i = 0; i < rsaBits->Length; i++)
					{
						// выполнить тестирование
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
				// удалить контейнер
				finally { containerHKCU->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKCU); }
			}
			// указать провайдер
			Using<Provider^> providerStrongRSA(gcnew RSA::StrongProvider()); 
			{ 
				Provider^ provider = providerStrongRSA.Get();  

				// перечислить контейнеры
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// указать размер ключей RSA в битах
				array<int>^ rsaBits = gcnew array<int> { 384, 512, 1024, 1536, 2048 }; 

				// выполнить тест
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

				// создать контейнер
				CAPI::Container^ containerHKLM = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKLM);
				try {
					// создать генератор случайных данных
					Using<IRand^> rand(provider->CreateRand(containerHKLM, window)); 

					// для всех размеров ключей
					for (int i = 0; i < rsaBits->Length; i++)
					{
						// выполнить тестирование
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
				// удалить контейнер
				finally { containerHKLM->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKLM); }

				// создать контейнер
				CAPI::Container^ containerHKCU = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKCU);
				try {
					// создать генератор случайных данных
					Using<IRand^> rand(provider->CreateRand(containerHKCU, window)); 

					// для всех размеров ключей
					for (int i = 0; i < rsaBits->Length; i++)
					{
						// выполнить тестирование
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
				// удалить контейнер
				finally { containerHKCU->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKCU); }
			}
			// указать провайдер
			Using<Provider^> providerEnhancedAES(gcnew RSA::AESEnhancedProvider()); 
			{ 
				Provider^ provider = providerEnhancedAES.Get();  

				// перечислить контейнеры
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// указать размер ключей RSA в битах
				array<int>^ rsaBits = gcnew array<int> { 384, 512, 1024, 1536, 2048 }; 

				// выполнить тест
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

				// проверить версию Windows
				if (IsWindows(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 3)) 
				{
					ANSI::Test::TestSHA2_256(provider, nullptr);
					ANSI::Test::TestSHA2_384(provider, nullptr);
					ANSI::Test::TestSHA2_512(provider, nullptr);

					ANSI::Test::TestHMAC_SHA2_256(provider, nullptr); 
					ANSI::Test::TestHMAC_SHA2_384(provider, nullptr); 
					ANSI::Test::TestHMAC_SHA2_512(provider, nullptr); 
				}
				// создать контейнер
				CAPI::Container^ containerHKLM = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKLM);
				try {
					// создать генератор случайных данных
					Using<IRand^> rand(provider->CreateRand(containerHKLM, window)); 

					// для всех размеров ключей
					for (int i = 0; i < rsaBits->Length; i++)
					{
						// выполнить тестирование
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
				// удалить контейнер
				finally { containerHKLM->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKLM); }

				// создать контейнер
				CAPI::Container^ containerHKCU = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKCU);
				try {
					// создать генератор случайных данных
					Using<IRand^> rand(provider->CreateRand(containerHKCU, window)); 

					// для всех размеров ключей
					for (int i = 0; i < rsaBits->Length; i++)
					{
						// выполнить тестирование
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
				// удалить контейнер
				finally { containerHKCU->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKCU); }
			}
			// указать провайдер
			Using<Provider^> providerBaseDSS(gcnew DSS::BaseProvider()); 
			{ 
				Provider^ provider = providerBaseDSS.Get();  

				// перечислить контейнеры
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// выполнить тест
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

				// создать контейнер
				CAPI::Container^ containerHKLM = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKLM);
				try {
					// создать генератор случайных данных
					Using<IRand^> rand(provider->CreateRand(containerHKLM, window)); 

					// выполнить тестирование
					ANSI::Test::TestDSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::None      ); 
					ANSI::Test::TestDSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::Exportable); 
					ANSI::Test::TestDSA(provider, containerHKLM, rand.Get(), false, KeyFlags::None      ); 
					ANSI::Test::TestDSA(provider, containerHKLM, rand.Get(), false, KeyFlags::Exportable); 
					ANSI::Test::TestDH (provider, containerHKLM, rand.Get(), true,  KeyFlags::None      ); 
					ANSI::Test::TestDH (provider, containerHKLM, rand.Get(), true,  KeyFlags::Exportable); 
					ANSI::Test::TestDH (provider, containerHKLM, rand.Get(), false, KeyFlags::None      ); 
					ANSI::Test::TestDH (provider, containerHKLM, rand.Get(), false, KeyFlags::Exportable); 
				}
				// удалить контейнер
				finally { containerHKLM->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKLM); }

				// создать контейнер
				CAPI::Container^ containerHKCU = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKCU);
				try {
					// создать генератор случайных данных
					Using<IRand^> rand(provider->CreateRand(containerHKCU, window)); 

					// выполнить тестирование
					ANSI::Test::TestDSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::None      ); 
					ANSI::Test::TestDSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::Exportable); 
					ANSI::Test::TestDSA(provider, containerHKCU, rand.Get(), false, KeyFlags::None      ); 
					ANSI::Test::TestDSA(provider, containerHKCU, rand.Get(), false, KeyFlags::Exportable); 
					ANSI::Test::TestDH (provider, containerHKCU, rand.Get(), true,  KeyFlags::None      ); 
					ANSI::Test::TestDH (provider, containerHKCU, rand.Get(), true,  KeyFlags::Exportable); 
					ANSI::Test::TestDH (provider, containerHKCU, rand.Get(), false, KeyFlags::None      ); 
					ANSI::Test::TestDH (provider, containerHKCU, rand.Get(), false, KeyFlags::Exportable); 
				}
				// удалить контейнер
				finally { containerHKCU->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKCU); }
			}
			// указать провайдер
			Using<Provider^> providerEnhancedDSS(gcnew DSS::EnhancedProvider()); 
			{ 
				Provider^ provider = providerEnhancedDSS.Get();  

				// перечислить контейнеры
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// выполнить тест
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

				// создать контейнер
				CAPI::Container^ containerHKLM = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKLM);
				try {
					// создать генератор случайных данных
					Using<IRand^> rand(provider->CreateRand(containerHKLM, window)); 

					// выполнить тестирование
					ANSI::Test::TestDSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::None      ); 
					ANSI::Test::TestDSA(provider, containerHKLM, rand.Get(), true,  KeyFlags::Exportable); 
					ANSI::Test::TestDSA(provider, containerHKLM, rand.Get(), false, KeyFlags::None      ); 
					ANSI::Test::TestDSA(provider, containerHKLM, rand.Get(), false, KeyFlags::Exportable); 
					ANSI::Test::TestDH (provider, containerHKLM, rand.Get(), true,  KeyFlags::None      ); 
					ANSI::Test::TestDH (provider, containerHKLM, rand.Get(), true,  KeyFlags::Exportable); 
					ANSI::Test::TestDH (provider, containerHKLM, rand.Get(), false, KeyFlags::None      ); 
					ANSI::Test::TestDH (provider, containerHKLM, rand.Get(), false, KeyFlags::Exportable); 
				}
				// удалить контейнер
				finally { containerHKLM->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKLM); }

				// создать контейнер
				CAPI::Container^ containerHKCU = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoHKCU);
				try {
					// создать генератор случайных данных
					Using<IRand^> rand(provider->CreateRand(containerHKCU, window)); 

					// выполнить тестирование
					ANSI::Test::TestDSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::None      ); 
					ANSI::Test::TestDSA(provider, containerHKCU, rand.Get(), true,  KeyFlags::Exportable); 
					ANSI::Test::TestDSA(provider, containerHKCU, rand.Get(), false, KeyFlags::None      ); 
					ANSI::Test::TestDSA(provider, containerHKCU, rand.Get(), false, KeyFlags::Exportable); 
					ANSI::Test::TestDH (provider, containerHKCU, rand.Get(), true,  KeyFlags::None      ); 
					ANSI::Test::TestDH (provider, containerHKCU, rand.Get(), true,  KeyFlags::Exportable); 
					ANSI::Test::TestDH (provider, containerHKCU, rand.Get(), false, KeyFlags::None      ); 
					ANSI::Test::TestDH (provider, containerHKCU, rand.Get(), false, KeyFlags::Exportable); 
				}
				// удалить контейнер
				finally { containerHKCU->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoHKCU); }
			}
			// указать провайдер
			Using<Provider^> providerSCardRSA(gcnew RSA::SCardProvider()); 
			{ 
				Provider^ provider = providerSCardRSA.Get();  

				// перечислить контейнеры
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// указать имя контейнера
				SecurityInfo^ infoCard = gcnew SecurityInfo(Scope::System, "Card\\ARDS JaCarta 0\\CAPI-TEST"); 

				// указать размер ключей RSA в битах
				array<int>^ rsaBits = gcnew array<int> { 512, 1024, 1536, 2048 }; 

				// выполнить тест
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

				// проверить версию Windows
				if (IsWindows(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 3)) 
				{
					ANSI::Test::TestSHA2_256(provider, nullptr);
					ANSI::Test::TestSHA2_384(provider, nullptr);
					ANSI::Test::TestSHA2_512(provider, nullptr);

					ANSI::Test::TestHMAC_SHA2_256(provider, nullptr); 
					ANSI::Test::TestHMAC_SHA2_384(provider, nullptr); 
					ANSI::Test::TestHMAC_SHA2_512(provider, nullptr); 
				}
				// создать контейнер
				CAPI::Container^ containerCard = GUI::AuthenticationSelector::OpenOrCreate(window, provider, infoCard);
				try {
					// создать генератор случайных данных
					Using<IRand^> rand(provider->CreateRand(containerCard, window)); 

					// для всех размеров ключей
					for (int i = 0; i < rsaBits->Length; i++)
					{
						// выполнить тестирование
						ANSI::Test::TestRSA(provider, containerCard, rand.Get(), true,  KeyFlags::None, rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerCard, rand.Get(), false, KeyFlags::None, rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, containerCard, rand.Get(), true,  KeyFlags::None, rsaBits[i], KeySizes::Range(16, 32, 8)); 
						ANSI::Test::TestRSA(provider, containerCard, rand.Get(), false, KeyFlags::None, rsaBits[i], KeySizes::Range(16, 32, 8)); 
					}
				}
				// удалить контейнер
				finally { containerCard->Release(); GUI::AuthenticationSelector::Delete(window, provider, infoCard); }
			}
		}
    };
}}}}}
