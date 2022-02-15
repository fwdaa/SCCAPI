#pragma once

#include "Container.h"

using namespace System::Collections::Generic; 

namespace Aladdin { namespace CAPI { namespace CNG 
{
	ref class PasswordProvider; 

	///////////////////////////////////////////////////////////////////////////
	// Кэш паролей
	///////////////////////////////////////////////////////////////////////////
	public interface class IPasswordCache
	{
		// добавить пароль в кэш
		public: virtual void SetPassword(String^ container, String^ password) = 0; 

		// список возможных паролей из кэша
		public: virtual array<String^>^ GetPasswords(String^ container) = 0; 
	}; 
	///////////////////////////////////////////////////////////////////////////
	// Неподдерживаемый кэш паролей
	///////////////////////////////////////////////////////////////////////////
	public ref class NoPasswordCache : IPasswordCache
	{
		// добавить пароль в кэш
		public: virtual void SetPassword(String^ container, String^ password) {} 

		// список возможных паролей из кэша
		public: virtual array<String^>^ GetPasswords(String^ container) 
		{
			// кэш паролей не поддерживается
			return gcnew array<String^>(0); 
		}
	}; 
	///////////////////////////////////////////////////////////////////////////
	// Кэш паролей по отдельным контейнерам
	///////////////////////////////////////////////////////////////////////////
	public ref class ContainerPasswordCache : IPasswordCache
	{
		// пароли контейнеров
		private: Dictionary<String^, List<String^>^>^ passwords;

		// конструктор
		public: ContainerPasswordCache()
		{
			// создать пустой список паролей
			passwords = gcnew Dictionary<String^, List<String^>^>(); 
		}
		// добавить пароль в кэш
		public: virtual void SetPassword(String^ container, String^ password); 

		// список возможных паролей из кэша
		public: virtual array<String^>^ GetPasswords(String^ container);

		// получить имя контейнера без имени считывателя
		protected: virtual String^ GetContainerName(String^ container); 
	}; 
	///////////////////////////////////////////////////////////////////////////
	// Действие, производимое после аутентификации
	///////////////////////////////////////////////////////////////////////////
	public interface class IPasswordAction
	{
		// выполнить действие без указания пароля
		public: virtual Object^ Invoke() = 0; 

		// выполнить действие с указанием пароля
		public: virtual Object^ PasswordInvoke(String^ password) = 0; 
	}; 
	///////////////////////////////////////////////////////////////////////////
	// Создание контейнера
	///////////////////////////////////////////////////////////////////////////
	public ref class CreateContainerAction : IPasswordAction
	{
		// используемый провайдер и имя контейнера
		private: PasswordProvider^ provider; private: String^ container; 
	
		// имя контейнера, режим открытия и функция обратного вызова
		private: DWORD flags; private: PasswordCallback^ callback;

		// конструктор
		public: CreateContainerAction(PasswordProvider^ provider, 
			String^ container, DWORD flags, PasswordCallback^ callback) 
		{
			// сохранить переданные параметры
			this->provider = provider; this->container = container; 
			
			// сохранить переданные параметры
			this->flags = flags; this->callback = callback; 
		}
		// выполнить действие без указания пароля
		public: virtual Object^ Invoke(); 

		// выполнить действие с указанием пароля
		public: virtual Object^ PasswordInvoke(String^ password); 
	}; 
	///////////////////////////////////////////////////////////////////////////
	// Удаление контейнера
	///////////////////////////////////////////////////////////////////////////
	public ref class DeleteContainerAction : IPasswordAction
	{
		// провайдер и имя контейнера
		private: PasswordProvider^ provider; private: String^ container; 

		// конструктор
		public: DeleteContainerAction(PasswordProvider^ provider, String^ container) 
		{
			// сохранить переданные параметры
			this->provider = provider; this->container = container; 
		}
		// выполнить действие без указания пароля
		public: virtual Object^ Invoke(); 

		// выполнить действие с указанием пароля
		public: virtual Object^ PasswordInvoke(String^ password); 
	};
	///////////////////////////////////////////////////////////////////////////
	// Действие с контейнером, производимое после аутентификации
	///////////////////////////////////////////////////////////////////////////
	public ref class ContainerPasswordAction abstract : IPasswordAction
	{
		// используемый контейнер
		private: CSP::Container^ container;

		// конструктор
		public: ContainerPasswordAction(CSP::Container^ container) 
		{
			// сохранить используемый контейнер
			this->container = container; 
		}
		// используемый контейнер
		public: property CSP::Container^ Container 
		{ 
			// используемый контейнер
			CSP::Container^ get() { return container; }
		}
		// выполнить действие без указания пароля
		public: virtual Object^ Invoke() = 0; 

		// выполнить действие с указанием пароля
		public: virtual Object^ PasswordInvoke(String^ password); 
	}; 
	/////////////////////////////////////////////////
	// Установка сертификата
	/////////////////////////////////////////////////
	private ref class SetCertificateAction : ContainerPasswordAction
	{
		// открытый ключ и сертификат
		private: KeyHandle hPublicKey; private: Binary^ certificate;
				 
		// конструктор
		public: SetCertificateAction(CSP::Container^ container, KeyHandle hPublicKey, 
			Binary^ certificate) : ContainerPasswordAction(container)
		{
			// сохранить переданные параметры
			this->hPublicKey = hPublicKey; this->certificate = certificate;
		}
		// сгенерировать пару ключей
		public: virtual Object^ Invoke() override
		{
			// установить сертификат
			hPublicKey->SetParam(KP_CERTIFICATE, certificate, 0); return nullptr; 
		}
	};
	/////////////////////////////////////////////////
	// Генерация пары ключей
	/////////////////////////////////////////////////
	private ref class GenerateKeyAction : ContainerPasswordAction
	{
		// тип ключа и режим генерации
		private: ALG_ID algID; private: DWORD flags;
				 
		// конструктор
		public: GenerateKeyAction(CSP::Container^ container, ALG_ID algID, DWORD flags)
			: ContainerPasswordAction(container)
		{
			// сохранить переданные параметры
			this->algID = algID; this->flags = flags;
		}
		// сгенерировать пару ключей
		public: virtual Object^ Invoke() override
		{
			// сгенерировать пару ключей
			return Container->Handle->Context.GenerateKey(algID, flags); 
		}
	};
	/////////////////////////////////////////////////
	// Импорт ключа
	/////////////////////////////////////////////////
	private ref class ImportKeyAction : ContainerPasswordAction
	{
		// ключ для импорта и импортируемые данные
		private: KeyHandle hImportKey; private: Binary^ data; private: DWORD flags;

		// конструктор
		public: ImportKeyAction(CSP::Container^ container, KeyHandle hImportKey, Binary^ data, DWORD flags)
			: ContainerPasswordAction(container)
		{
			// сохранить переданные параметры
			this->hImportKey = hImportKey; this->data = data; this->flags = flags;
		}
		// импортировать ключ в контейнер
		public: virtual Object^ Invoke() override
		{
			// импортировать ключ в контейнер
			return Container->Handle->Context.ImportKey(hImportKey, data, flags); 
		}
	};
	/////////////////////////////////////////////////
	// Расшифровать данные
	/////////////////////////////////////////////////
	private ref class DecryptAction : ContainerPasswordAction
	{
		// описатель ключа и расшифровываемые данные
		private: KeyHandle hKey; private: Binary^ data; private: DWORD flags;

		// конструктор
		public: DecryptAction(CSP::Container^ container, KeyHandle hKey, Binary^ data, DWORD flags)
			: ContainerPasswordAction(container)
		{
			// сохранить переданные параметры
			this->hKey = hKey; this->data = data; this->flags = flags;
		}
		// расшифровать данные
		public: virtual Object^ Invoke() override { return hKey->Decrypt(data, flags); } 
	};
	/////////////////////////////////////////////////
	// Подпись хэш-значения
	/////////////////////////////////////////////////
	private ref class SignHashAction : ContainerPasswordAction
	{
		// тип ключа и описатель алгоритма хэширования 
		private: DWORD keyType; private: HashHandle hHash; private: DWORD flags; 

		// конструктор
		public: SignHashAction(CSP::Container^ container, DWORD keyType, HashHandle hHash, DWORD flags)
			: ContainerPasswordAction(container)
		{
			// сохранить переданные параметры
			this->keyType = keyType; this->hHash = hHash; this->flags = flags; 
		}
		// подписать хэш-значение
		public: virtual Object^ Invoke() override
		{ 
			// подписать хэш-значение
			return Container->Handle->SignHash(keyType, hHash, flags); 
		} 
	};
}}}
