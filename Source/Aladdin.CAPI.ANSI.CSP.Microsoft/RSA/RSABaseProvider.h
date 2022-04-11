#pragma once
#include "RSAProvider.h"
#include "..\RegistryStore.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace RSA 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптопровайдер Base Cryptographic Provider
	///////////////////////////////////////////////////////////////////////////
	public ref class BaseProvider : Provider
	{
		// конструктор
		public: BaseProvider() : Provider(PROV_RSA_FULL, MS_DEF_PROV_W, false, true) 
		{
			// заполнить список фабрик кодирования ключей
			SecretKeyFactories()->Add("RC2" , gcnew Keys::RC2 (KeySizes::Range(5, 7))); 
			SecretKeyFactories()->Add("RC4" , gcnew Keys::RC4 (KeySizes::Range(5, 7))); 
			SecretKeyFactories()->Add("DES" , gcnew Keys::DES (                     )); 
			SecretKeyFactories()->Add("DESX", gcnew Keys::DESX(                     )); 
		}
		// конструктор
		protected: BaseProvider(DWORD type, String^ name, bool sspi, bool oaep) 

			// сохранить переданные параметры
			: Provider(type, name, sspi, oaep) 
		{
			// заполнить список фабрик кодирования ключей
			SecretKeyFactories()->Add("RC2" , gcnew Keys::RC2 (KeySizes::Range(5, 7))); 
			SecretKeyFactories()->Add("RC4" , gcnew Keys::RC4 (KeySizes::Range(5, 7))); 
			SecretKeyFactories()->Add("DES" , gcnew Keys::DES (                     )); 
			SecretKeyFactories()->Add("DESX", gcnew Keys::DESX(                     )); 
		}
		// имя группы провайдеров
		public: virtual property String^ Group { String^ get() override 
		{ 
			// имя группы провайдеров
			return "Microsoft Enhanced RSA and AES Cryptographic Provider"; 
		}}
		// имя провайдера
		public: virtual property String^ Name { String^ get() override 
		{ 
			// имя провайдера
			return "Microsoft Base Cryptographic Provider"; 
		}}
		// перечислить хранилища контейнеров
		public: virtual array<String^>^ EnumerateStores(Scope scope) override
		{
			// создать список имен
			List<String^>^ names = gcnew List<String^>(); 

			// указать имена хранилищ
			if (scope == Scope::System) names->Add("HKLM"); 
			if (scope == Scope::User  ) names->Add("HKCU"); 

			// вернуть список имен
			return names->ToArray(); 
		}
		// получить хранилище контейнера
		public: virtual SecurityStore^ OpenStore(Scope scope, String^ name) override
		{
			// вернуть хранилище контейнеров
			return gcnew RegistryStore(this, scope);
		}
		// создать алгоритм для параметров
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, String^ oid, 
			ASN1::IEncodable^ parameters, System::Type^ type) override;
	}; 
}}}}}}
