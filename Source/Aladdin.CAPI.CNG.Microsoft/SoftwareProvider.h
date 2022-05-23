#pragma once
#include "Provider.h"
#include "RegistryStore.h"

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft
{
	///////////////////////////////////////////////////////////////////////////
	// Криптографический провайдер
	///////////////////////////////////////////////////////////////////////////
	public ref class SoftwareProvider : Provider
	{
		// конструктор
		public: SoftwareProvider() : Provider("Microsoft Software Key Storage Provider") {}

		// получить хранилище контейнера
		public: virtual array<String^>^ EnumerateStores(Scope scope) override 
		{ 
			// вернуть имена хранилищ контейнеров
			if (scope == Scope::System) return gcnew array<String^> { "HKLM" }; 
			if (scope == Scope::User  ) return gcnew array<String^> { "HKCU" }; 

			return gcnew array<String^>(0); 
		}
		// получить хранилище контейнера
		public: virtual SecurityStore^ OpenStore(Scope scope, String^ name) override 
		{ 
			// проверить совпадение имени
			if (scope == Scope::System && name != "HKLM")
			{
				// при ошибке выбросить исключение
				throw gcnew NotFoundException(); 
			}
			// проверить совпадение имени
			if (scope == Scope::User && name != "HKCU")
			{
				// при ошибке выбросить исключение
				throw gcnew NotFoundException(); 
			}
			// вернуть хранилище контейнеров
			return gcnew RegistryStore(this, scope);
		}
	};
}}}}