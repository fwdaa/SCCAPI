#include "stdafx.h"
#include "Provider2001.h"
#include "Provider2012_256.h"
#include "Provider2012_512.h"

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro
{
	public ref class Test abstract sealed
	{
		public: static void TestContainer2001(IWin32Window^ window, Provider^ provider, SecurityInfo^ info)
        {
			// указать способ шифрования ключа
            int wrapFlags = 
                CAPI::GOST::Wrap::RFC4357::NoneSBoxA | CAPI::GOST::Wrap::RFC4357::NoneSBoxB | 
                CAPI::GOST::Wrap::RFC4357::NoneSBoxC | CAPI::GOST::Wrap::RFC4357::NoneSBoxD |
                CAPI::GOST::Wrap::RFC4357::CProSBoxA | CAPI::GOST::Wrap::RFC4357::CProSBoxB | 
                CAPI::GOST::Wrap::RFC4357::CProSBoxC | CAPI::GOST::Wrap::RFC4357::CProSBoxD ; 
                
			// создать контейнер
			CAPI::Container^ container = GUI::AuthenticationSelector::OpenOrCreate(window, provider, info);
			try { 
				// удалить ключи контейнера
				container->DeleteKeys();

				// создать генератор случайных данных
				Using<IRand^> rand(provider->CreateRand(container, window)); 

				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), true, KeyFlags::None, 
					ASN1::GOST::OID::ecc_signs_A, ASN1::GOST::OID::hashes_cryptopro, nullptr, 0
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), true, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_signs_A, ASN1::GOST::OID::hashes_cryptopro, nullptr, 0
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), false, KeyFlags::None, 
					ASN1::GOST::OID::ecc_signs_A, ASN1::GOST::OID::hashes_cryptopro, nullptr, 0
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), false, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_signs_A, ASN1::GOST::OID::hashes_cryptopro, nullptr, 0
				); 

				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), true, KeyFlags::None, 
					ASN1::GOST::OID::ecc_signs_B, ASN1::GOST::OID::hashes_cryptopro, nullptr, 0
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), true, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_signs_B, ASN1::GOST::OID::hashes_cryptopro, nullptr, 0
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), false, KeyFlags::None, 
					ASN1::GOST::OID::ecc_signs_B, ASN1::GOST::OID::hashes_cryptopro, nullptr, 0
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), false, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_signs_B, ASN1::GOST::OID::hashes_cryptopro, nullptr, 0
				); 

				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), true, KeyFlags::None, 
					ASN1::GOST::OID::ecc_signs_C, ASN1::GOST::OID::hashes_cryptopro, nullptr, 0
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), true, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_signs_C, ASN1::GOST::OID::hashes_cryptopro, nullptr, 0
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), false, KeyFlags::None, 
					ASN1::GOST::OID::ecc_signs_C, ASN1::GOST::OID::hashes_cryptopro, nullptr, 0
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), false, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_signs_C, ASN1::GOST::OID::hashes_cryptopro, nullptr, 0
				); 

				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), true, KeyFlags::None, 
					ASN1::GOST::OID::ecc_exchanges_A, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_A, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), true, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_exchanges_A, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_A, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), false, KeyFlags::None, 
					ASN1::GOST::OID::ecc_exchanges_A, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_A, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), false, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_exchanges_A, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_A, wrapFlags
				); 

				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), true, KeyFlags::None, 
					ASN1::GOST::OID::ecc_exchanges_A, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_B, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), true, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_exchanges_A, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_B, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), false, KeyFlags::None, 
					ASN1::GOST::OID::ecc_exchanges_A, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_B, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), false, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_exchanges_A, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_B, wrapFlags
				); 

				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), true, KeyFlags::None, 
					ASN1::GOST::OID::ecc_exchanges_A, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_C, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), true, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_exchanges_A, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_C, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), false, KeyFlags::None, 
					ASN1::GOST::OID::ecc_exchanges_A, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_C, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), false, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_exchanges_A, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_C, wrapFlags
				); 

				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), true, KeyFlags::None, 
					ASN1::GOST::OID::ecc_exchanges_A, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_D, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), true, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_exchanges_A, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_D, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), false, KeyFlags::None, 
					ASN1::GOST::OID::ecc_exchanges_A, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_D, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), false, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_exchanges_A, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_D, wrapFlags
				); 

				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), true, KeyFlags::None, 
					ASN1::GOST::OID::ecc_exchanges_B, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_A, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), true, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_exchanges_B, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_A, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), false, KeyFlags::None, 
					ASN1::GOST::OID::ecc_exchanges_B, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_A, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), false, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_exchanges_B, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_A, wrapFlags
				); 

				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), true, KeyFlags::None, 
					ASN1::GOST::OID::ecc_exchanges_B, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_B, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), true, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_exchanges_B, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_B, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), false, KeyFlags::None, 
					ASN1::GOST::OID::ecc_exchanges_B, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_B, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), false, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_exchanges_B, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_B, wrapFlags
				); 

				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), true, KeyFlags::None, 
					ASN1::GOST::OID::ecc_exchanges_B, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_C, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), true, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_exchanges_B, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_C, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), false, KeyFlags::None, 
					ASN1::GOST::OID::ecc_exchanges_B, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_C, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), false, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_exchanges_B, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_C, wrapFlags
				); 

				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), true, KeyFlags::None, 
					ASN1::GOST::OID::ecc_exchanges_B, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_D, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), true, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_exchanges_B, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_D, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), false, KeyFlags::None, 
					ASN1::GOST::OID::ecc_exchanges_B, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_D, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2001(
					provider, container, rand.Get(), false, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_exchanges_B, ASN1::GOST::OID::hashes_cryptopro, 
					ASN1::GOST::OID::encrypts_D, wrapFlags
				); 
			}
			// удалить контейнер
			finally { container->Release(); GUI::AuthenticationSelector::Delete(window, provider, info); }
		}
		public: static void TestContainer2012_256(IWin32Window^ window, Provider^ provider, SecurityInfo^ info)
        {
			// указать размеры ключей шифрования
			array<int>^ keySizes = gcnew array<int> { 32 }; 

			// указать способ шифрования ключа
            int wrapFlags  = 
                CAPI::GOST::Wrap::RFC4357::NoneSBoxA | CAPI::GOST::Wrap::RFC4357::NoneSBoxB | 
                CAPI::GOST::Wrap::RFC4357::NoneSBoxC | CAPI::GOST::Wrap::RFC4357::NoneSBoxD |
                CAPI::GOST::Wrap::RFC4357::CProSBoxA | CAPI::GOST::Wrap::RFC4357::CProSBoxB | 
                CAPI::GOST::Wrap::RFC4357::CProSBoxC | CAPI::GOST::Wrap::RFC4357::CProSBoxD | 
				CAPI::GOST::Wrap::RFC4357::NoneSBoxZ | CAPI::GOST::Wrap::RFC4357::CProSBoxZ; 
                
			// создать контейнер
			CAPI::Container^ container = GUI::AuthenticationSelector::OpenOrCreate(window, provider, info);
			try { 
				// удалить ключи контейнера
				container->DeleteKeys();

				// создать генератор случайных данных
				Using<IRand^> rand(provider->CreateRand(container, window)); 

				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), true, KeyFlags::None, 
					ASN1::GOST::OID::ecc_signs_A, nullptr, 0
				); 
				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), true, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_signs_A, nullptr, 0
				); 
				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), false, KeyFlags::None, 
					ASN1::GOST::OID::ecc_signs_A, nullptr, 0
				); 
				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), false, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_signs_A, nullptr, 0
				); 

				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), true, KeyFlags::None, 
					ASN1::GOST::OID::ecc_signs_B, nullptr, 0
				); 
				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), true, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_signs_B, nullptr, 0
				); 
				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), false, KeyFlags::None, 
					ASN1::GOST::OID::ecc_signs_B, nullptr, 0
				); 
				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), false, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_signs_B, nullptr, 0
				); 

				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), true, KeyFlags::None, 
					ASN1::GOST::OID::ecc_signs_C, nullptr, 0
				); 
				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), true, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_signs_C, nullptr, 0
				); 
				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), false, KeyFlags::None, 
					ASN1::GOST::OID::ecc_signs_C, nullptr, 0
				); 
				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), false, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_signs_C, nullptr, 0
				); 

				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), true, KeyFlags::None, 
					ASN1::GOST::OID::ecc_exchanges_A, keySizes, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), true, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_exchanges_A, keySizes, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), false, KeyFlags::None, 
					ASN1::GOST::OID::ecc_exchanges_A, keySizes, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), false, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_exchanges_A, keySizes, wrapFlags
				); 

				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), true, KeyFlags::None, 
					ASN1::GOST::OID::ecc_exchanges_B, keySizes, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), true, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_exchanges_B, keySizes, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), false, KeyFlags::None, 
					ASN1::GOST::OID::ecc_exchanges_B, keySizes, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), false, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_exchanges_B, keySizes, wrapFlags
				); 
				///////////////////////////////////////////////////////////////
				// Для идентификатора ecc_tc26_2012_256A алгоритм TransportKeyWrap 
				// от КриптоПро неправильно интерпретирует создаваемую извне 
				// структуру зашифрованного ключа (свои структуры распознаются). 
				// Возможно используестся другой набор параметров эллиптических 
				// кривых вместо ecc_tc26_2012_256A
				///////////////////////////////////////////////////////////////
				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), true, KeyFlags::None, 
					ASN1::GOST::OID::ecc_tc26_2012_256A, nullptr, 0
				); 
				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), true, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_tc26_2012_256A, nullptr, 0
				); 
				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), false, KeyFlags::None, 
					ASN1::GOST::OID::ecc_tc26_2012_256A, nullptr, 0
				); 
				GOST::Test::TestGOSTR3410_2012_256(
					provider, container, rand.Get(), false, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_tc26_2012_256A, nullptr, 0
				); 
			}
			// удалить контейнер
			finally { container->Release(); GUI::AuthenticationSelector::Delete(window, provider, info); }
		}
		public: static void TestContainer2012_512(IWin32Window^ window, Provider^ provider, SecurityInfo^ info)
        {
			// указать размеры ключей шифрования
			array<int>^ keySizes = gcnew array<int> { 32, 64 }; 

			// указать способ шифрования ключа
            int wrapFlags  = 
                CAPI::GOST::Wrap::RFC4357::NoneSBoxA | CAPI::GOST::Wrap::RFC4357::NoneSBoxB | 
                CAPI::GOST::Wrap::RFC4357::NoneSBoxC | CAPI::GOST::Wrap::RFC4357::NoneSBoxD |
                CAPI::GOST::Wrap::RFC4357::CProSBoxA | CAPI::GOST::Wrap::RFC4357::CProSBoxB | 
                CAPI::GOST::Wrap::RFC4357::CProSBoxC | CAPI::GOST::Wrap::RFC4357::CProSBoxD | 
				CAPI::GOST::Wrap::RFC4357::NoneSBoxZ | CAPI::GOST::Wrap::RFC4357::CProSBoxZ; 
                
			// создать контейнер
			CAPI::Container^ container = GUI::AuthenticationSelector::OpenOrCreate(window, provider, info);
			try { 
				// удалить ключи контейнера
				container->DeleteKeys();

				// создать генератор случайных данных
				Using<IRand^> rand(provider->CreateRand(container, window)); 

				GOST::Test::TestGOSTR3410_2012_512(
					provider, container, rand.Get(), true, KeyFlags::None, 
					ASN1::GOST::OID::ecc_tc26_2012_512A, keySizes, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2012_512(
					provider, container, rand.Get(), true, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_tc26_2012_512A, keySizes, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2012_512(
					provider, container, rand.Get(), false, KeyFlags::None, 
					ASN1::GOST::OID::ecc_tc26_2012_512A, keySizes, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2012_512(
					provider, container, rand.Get(), false, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_tc26_2012_512A, keySizes, wrapFlags
				); 

				GOST::Test::TestGOSTR3410_2012_512(
					provider, container, rand.Get(), true, KeyFlags::None, 
					ASN1::GOST::OID::ecc_tc26_2012_512B, keySizes, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2012_512(
					provider, container, rand.Get(), true, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_tc26_2012_512B, keySizes, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2012_512(
					provider, container, rand.Get(), false, KeyFlags::None, 
					ASN1::GOST::OID::ecc_tc26_2012_512B, keySizes, wrapFlags
				); 
				GOST::Test::TestGOSTR3410_2012_512(
					provider, container, rand.Get(), false, KeyFlags::Exportable, 
					ASN1::GOST::OID::ecc_tc26_2012_512B, keySizes, wrapFlags
				); 
			}
			// удалить контейнер
			finally { container->Release(); GUI::AuthenticationSelector::Delete(window, provider, info); }
		}
		public: static void Entry()
		{
			// получить консольное окно
			IWin32Window^ window = Aladdin::GUI::Win32Window::FromHandle(IntPtr(GetConsoleWindow())); 

			// указать имя контейнера
			SecurityInfo^ infoHKLM = gcnew SecurityInfo(Scope::System, "HKLM\\HKLM-CAPI-TEST"); 
			SecurityInfo^ infoHKCU = gcnew SecurityInfo(Scope::User  , "HKCU\\HKCU-CAPI-TEST"); 
			SecurityInfo^ infoCard = gcnew SecurityInfo(
				// Scope::System, "Card\\Aladdin R.D. Token PRO 0\\CAPI-TEST"
				Scope::System, "Card\\ARDS JaCarta 0\\CAPI-TEST"
			); 
			// указать провайдер
			Using<Provider^> provider2001(gcnew Provider2001()); 
			{ 
				Provider^ provider = provider2001.Get(); 

				// перечислить контейнеры
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any   ); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User  ); 

				// идентификаторы наборов параметров
				array<String^>^ hashOIDs = gcnew array<String^> {
					ASN1::GOST::OID::hashes_test, ASN1::GOST::OID::hashes_cryptopro
				}; 
				// идентификаторы наборов параметров
				array<String^>^ sboxOIDs = gcnew array<String^> {
					ASN1::GOST::OID::encrypts_test, ASN1::GOST::OID::encrypts_A, 
					ASN1::GOST::OID::encrypts_B,    ASN1::GOST::OID::encrypts_C, 
					ASN1::GOST::OID::encrypts_D
				}; 
				// для всех наборов параметров
				for (int i = 0; i < sboxOIDs->Length; i++)
				{
					// выполнить тесты
					GOST::Test::TestMAC_GOST28147 (provider, nullptr, sboxOIDs[i]); 
				}
				// для всех наборов параметров
				for (int i = 0; i < sboxOIDs->Length; i++)
				{
					// выполнить тесты
					GOST::Test::TestGOST28147(provider, nullptr, sboxOIDs[i]); 
				}
				// для всех наборов параметров
				for (int i = 0; i < hashOIDs->Length; i++)
				{
					// выполнить тесты
					GOST::Test::TestGOSTR3411_1994(provider, nullptr, hashOIDs[i]); 
				}
				// для всех наборов параметров
				for (int i = 0; i < hashOIDs->Length; i++)
				{
					// выполнить тесты
					GOST::Test::TestHMAC_GOSTR3411_1994(provider, nullptr, hashOIDs[i]); 
				}
				// выполнить тесты
				TestContainer2001(window, provider, infoHKLM); 
				TestContainer2001(window, provider, infoHKCU); 
				TestContainer2001(window, provider, infoCard); 
			}
			// указать провайдер
			Using<Provider^> provider2012_256(gcnew Provider2012_256()); 
			{ 
				Provider^ provider = provider2012_256.Get(); 

				// перечислить контейнеры
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// идентификаторы наборов параметров
				array<String^>^ sboxOIDs = gcnew array<String^> {
					ASN1::GOST::OID::encrypts_test, ASN1::GOST::OID::encrypts_A, 
					ASN1::GOST::OID::encrypts_B,    ASN1::GOST::OID::encrypts_C, 
					ASN1::GOST::OID::encrypts_D,    ASN1::GOST::OID::encrypts_tc26_z
				}; 
				// для всех наборов параметров
				for (int i = 0; i < sboxOIDs->Length; i++)
				{
					// выполнить тесты
					GOST::Test::TestMAC_GOST28147 (provider, nullptr, sboxOIDs[i]); 
				}
				// для всех наборов параметров
				for (int i = 0; i < sboxOIDs->Length; i++)
				{
					// выполнить тесты
					GOST::Test::TestGOST28147(provider, nullptr, sboxOIDs[i]); 
				}
				// выполнить тесты
				GOST::Test::TestGOSTR3411_2012_256     (provider, nullptr); 
				GOST::Test::TestGOSTR3411_2012_512     (provider, nullptr); 
				GOST::Test::TestHMAC_GOSTR3411_2012_256(provider, nullptr); 
				GOST::Test::TestHMAC_GOSTR3411_2012_512(provider, nullptr); 
				GOST::Test::TestKDF_GOSTR3411_2012     (provider, nullptr); 

				// выполнить тест
				TestContainer2012_256(window, provider, infoHKLM); 
				TestContainer2012_256(window, provider, infoHKCU); 
				TestContainer2012_256(window, provider, infoCard); 
			}
			// указать провайдер
			Using<Provider^> provider2012_512(gcnew Provider2012_512()); 
			{ 
				Provider^ provider = provider2012_512.Get(); 

				// перечислить контейнеры
				array<SecurityInfo^>^ containersA = provider->EnumerateAllObjects(Scope::Any); 
				array<SecurityInfo^>^ containersS = provider->EnumerateAllObjects(Scope::System); 
				array<SecurityInfo^>^ containersU = provider->EnumerateAllObjects(Scope::User); 

				// идентификаторы наборов параметров
				array<String^>^ sboxOIDs = gcnew array<String^> {
					ASN1::GOST::OID::encrypts_test, ASN1::GOST::OID::encrypts_A, 
					ASN1::GOST::OID::encrypts_B,    ASN1::GOST::OID::encrypts_C, 
					ASN1::GOST::OID::encrypts_D,    ASN1::GOST::OID::encrypts_tc26_z
				}; 
				// для всех наборов параметров
				for (int i = 0; i < sboxOIDs->Length; i++)
				{
					// выполнить тесты
					GOST::Test::TestMAC_GOST28147 (provider, nullptr, sboxOIDs[i]); 
				}
				// для всех наборов параметров
				for (int i = 0; i < sboxOIDs->Length; i++)
				{
					// выполнить тесты
					GOST::Test::TestGOST28147(provider, nullptr, sboxOIDs[i]); 
				}
				// выполнить тесты
				GOST::Test::TestGOSTR3411_2012_256     (provider, nullptr); 
				GOST::Test::TestGOSTR3411_2012_512     (provider, nullptr); 
				GOST::Test::TestHMAC_GOSTR3411_2012_256(provider, nullptr); 
				GOST::Test::TestHMAC_GOSTR3411_2012_512(provider, nullptr); 
				GOST::Test::TestKDF_GOSTR3411_2012     (provider, nullptr); 

				// выполнить тесты
				TestContainer2012_512(window, provider, infoHKLM); 
				TestContainer2012_512(window, provider, infoHKCU); 
				TestContainer2012_512(window, provider, infoCard); 
			}
		}
    };
}}}}}
