#include "stdafx.h"
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace Athena
{
	public ref class Test abstract sealed
	{
		public: static void Entry()
		{
			// получить консольное окно
			IWin32Window^ window = Aladdin::GUI::Win32Window::FromHandle(IntPtr(GetConsoleWindow())); 

			// указать имя контейнера
			SecurityInfo^ info = gcnew SecurityInfo(
				Scope::System, "Card\\ARDS JaCarta 0\\CAPI-TEST"
			); 
			// указать провайдер
			Using<Provider^> providerAthena(gcnew Provider()); 
			{ 
				Provider^ provider = providerAthena.Get(); 

				// перечислить контейнеры
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// выполнить тест
				ANSI::Test::TestMD2      (provider, nullptr);
				ANSI::Test::TestMD4      (provider, nullptr);
				ANSI::Test::TestMD5      (provider, nullptr);
				ANSI::Test::TestSHA1     (provider, nullptr);
				ANSI::Test::TestHMAC_MD5 (provider, nullptr); 
				ANSI::Test::TestHMAC_SHA1(provider, nullptr); 
				ANSI::Test::TestRC2      (provider, nullptr); 
				ANSI::Test::TestRC4      (provider, nullptr); 
				ANSI::Test::TestDES      (provider, nullptr); 
				ANSI::Test::TestTDES     (provider, nullptr); 
				ANSI::Test::TestAES      (provider, nullptr); 

				// проверить версию Windows
				if (IsWindows(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 3)) 
				{
					ANSI::Test::TestSHA2_256     (provider, nullptr);
					ANSI::Test::TestSHA2_384     (provider, nullptr);
					ANSI::Test::TestSHA2_512     (provider, nullptr);
					ANSI::Test::TestHMAC_SHA2_256(provider, nullptr); 
					ANSI::Test::TestHMAC_SHA2_384(provider, nullptr); 
					ANSI::Test::TestHMAC_SHA2_512(provider, nullptr); 
				}
				// указать размер ключей RSA в битах
				array<int>^ rsaBits = gcnew array<int> { 512, 1024, 1536, 2048 }; 

				// создать контейнер
				CAPI::Container^ container = GUI::AuthenticationSelector::OpenOrCreate(window, provider, info);
				try {
					// создать генератор случайных данных
					Using<IRand^> rand(provider->CreateRand(container, window)); 

					// для всех размеров ключей
					for (int i = 0; i < rsaBits->Length; i++)
					{
						// выполнить тестирование
						ANSI::Test::TestRSA(provider, container, rand.Get(), true,  KeyFlags::None, rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, container, rand.Get(), false, KeyFlags::None, rsaBits[i], KeySizes::Range( 5, 16, 1)); 
						ANSI::Test::TestRSA(provider, container, rand.Get(), true,  KeyFlags::None, rsaBits[i], KeySizes::Range(16, 32, 8)); 
						ANSI::Test::TestRSA(provider, container, rand.Get(), false, KeyFlags::None, rsaBits[i], KeySizes::Range(16, 32, 8)); 
					}
				}
				// удалить контейнер
				finally { container->Release(); GUI::AuthenticationSelector::Delete(window, provider, info); }
			}
		}
    };
}}}}
