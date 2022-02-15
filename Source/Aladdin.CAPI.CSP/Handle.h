#pragma once

namespace Aladdin { namespace CAPI { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////////
	// Описатель объекта
	///////////////////////////////////////////////////////////////////////////
	public ref class Handle abstract : SafeHandle
	{
		// увеличить счетчик ссылок
		public:	generic <typename T> where T : Handle static T AddRef(T handle) 
		{ 
			// увеличить счетчик ссылок
			bool success = false; handle->DangerousAddRef(IN OUT success); 
			
			// проверить отсуствие ошибок
			if (!success) throw gcnew Win32Exception(NTE_FAIL); return handle; 
		}
		// уменьшить счетчик ссылок
		public:	generic <typename T> where T : Handle static void Release(T handle) 
		{ 
			// уменьшить счетчик ссылок
			if (handle != nullptr) handle->DangerousRelease(); 
		}
		// конструктор
		public: Handle() : SafeHandle(IntPtr::Zero, true) {}

		// признак некорректного описателя
		public: virtual property bool IsInvalid 
		{ 
			// признак некорректного описателя
			[SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
			bool get() override { return handle == IntPtr::Zero; }
		}
		// освободить объект
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override
		{ 
			// отменить вызов деструктора
			GC::SuppressFinalize(this); return true; 
		} 
		// значение описателя
		public: property void* Value { void* get() { return handle.ToPointer(); }}   

		// получить параметр
		public: virtual DWORD GetSafeParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags) = 0; 
		// получить параметр
		public: virtual DWORD GetParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags) = 0; 
		// установить параметр
		public: virtual void SetParam(DWORD param, IntPtr ptr, DWORD flags) = 0; 

		// получить параметр алгоритма
		public: array<BYTE>^ GetSafeParam(DWORD param, DWORD flags); 
		// получить параметр алгоритма
		public: array<BYTE>^ GetParam(DWORD param, DWORD flags); 
		// получить параметр алгоритма
		public: String^ GetString(DWORD param, DWORD flags); 
		// получить параметр алгоритма
		public: DWORD GetLong(DWORD param, DWORD flags); 

		// установить параметр алгоритма
		public: void SetParam(DWORD param, array<BYTE>^ value, DWORD flags); 
		// установить параметр алгоритма
		public: void SetString(DWORD param, String^ value, DWORD flags); 
		// установить параметр алгоритма
		public: void SetLong(DWORD param, DWORD value, DWORD flags); 
	};
	///////////////////////////////////////////////////////////////////////////
	// Описатель алгоритма хэширования
	///////////////////////////////////////////////////////////////////////////
	public ref class HashHandle : Handle
	{
        // описатель провайдера и использование родного интерфейса
		private: Handle^ providerHandle; public: initonly BOOL SSPI; 

		// конструктор
		public: HashHandle(Handle^ providerHandle, HCRYPTHASH hHash, BOOL sspi) 
        { 
            // сохранить переданные параметры
            SetHandle((IntPtr)(PVOID)hHash); SSPI = sspi; 

			// сохранить описатель провайдера
			this->providerHandle = Handle::AddRef(providerHandle); 
        }  
		// освободить объект
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override; 

		// описатель провайдера
		public: property Handle^ ProviderHandle 
		{ 
			// описатель провайдера
			Handle^ get() { return providerHandle; }
		}   
		// описатель алгоритма хэширования
		public: property HCRYPTHASH Value
		{ 
			// описатель алгоритма хэширования
			HCRYPTHASH get() { return (HCRYPTHASH)handle.ToPointer(); }
		}   
		// создать копию алгоритма хэширования
		public: HashHandle^ Duplicate(DWORD flags); 

		// получить параметр алгоритма
		public: virtual DWORD GetSafeParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// получить параметр алгоритма
		public: virtual DWORD GetParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// установить параметр алгоритма
		public: virtual void SetParam(DWORD param, IntPtr ptr, DWORD flags) override; 

		// захэшировать данные 
		public: void HashData(array<BYTE>^ data, DWORD dataOff, DWORD dataLen, DWORD flags);
	};
	///////////////////////////////////////////////////////////////////////////
	// Описатель ключа
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyHandle: Handle
	{
        // описатель провайдера и использование родного интерфейса
		private: Handle^ providerHandle; public: initonly BOOL SSPI; 

		// конструктор
		public: KeyHandle(Handle^ providerHandle, HCRYPTKEY hKey, BOOL sspi) 
        {
            // сохранить переданные параметры
            SetHandle((IntPtr)(PVOID)hKey); SSPI = sspi; 

			// сохранить описатель провайдера
			this->providerHandle = Handle::AddRef(providerHandle); 
		} 
		// освободить объект
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override; 

		// описатель провайдера
		public: property Handle^ ProviderHandle 
		{ 
			// описатель провайдера
			Handle^ get() { return providerHandle; }
		}   
		// описатель ключа
		public: property HCRYPTKEY Value 
		{ 
			// описатель ключа
			HCRYPTKEY get() { return (HCRYPTKEY)handle.ToPointer(); }
		}   
		// создать копию ключа
		public: KeyHandle^ Duplicate(DWORD flags);

		// получить параметр алгоритма
		public: virtual DWORD GetSafeParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// получить параметр алгоритма
		public: virtual DWORD GetParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// установить параметр алгоритма
		public: virtual void SetParam(DWORD param, IntPtr ptr, DWORD flags) override; 

		// экспортировать ключ
		public: DWORD Export(KeyHandle^ hExportKey, DWORD blobType, 
			DWORD flags, IntPtr ptrBlob, DWORD cbBlob
		); 
		// зашифровать данные 
		public: DWORD Encrypt(array<BYTE>^ data, DWORD dataOff, DWORD dataLen, 
			BOOL final, DWORD flags, array<BYTE>^ buffer, DWORD bufferOff 
		); 
		// зашифровать данные 
		public: array<BYTE>^ Encrypt(array<BYTE>^ data, DWORD flags);

		// расшифровать данные 
		public: DWORD Decrypt(array<BYTE>^ data, DWORD dataOff, DWORD dataLen, 
			BOOL final, DWORD flags, array<BYTE>^ buffer, DWORD bufferOff 
		);
		// расшифровать данные 
		public: array<BYTE>^ Decrypt(array<BYTE>^ data, DWORD flags);

		// проверить подпись хэш-значения
		public: void VerifySignature(HashHandle^ hHash, array<BYTE>^ signature, DWORD flags);  
	}; 
	///////////////////////////////////////////////////////////////////////////
	// Описатель контекста
	///////////////////////////////////////////////////////////////////////////
	public ref class ContextHandle : Handle
	{
        // использование родного интерфейса
        public: initonly BOOL SSPI;

		// конструктор
		public: ContextHandle(HCRYPTPROV hContext, BOOL sspi) 
        {
            // сохранить переданные параметры        
            SetHandle((IntPtr)(PVOID)hContext); SSPI = sspi; 
        }
		// освободить объект
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override; 

		// описатель контекта
		public: property HCRYPTPROV Value 
		{ 
			// описатель контекта
			HCRYPTPROV get() { return (HCRYPTPROV)handle.ToPointer(); }
		}   
		// получить параметр 
		public: virtual DWORD GetSafeParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// получить параметр 
		public: virtual DWORD GetParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// установить параметр 
		public: virtual void SetParam(DWORD param, IntPtr ptr, DWORD flags) override; 

		// сгенерировать случайные данные
		public: void Generate(array<BYTE>^ buffer, DWORD bufferOff, DWORD bufferLen); 
		// создать алгоритм хэширования
		public: HashHandle^ CreateHash(ALG_ID algID, KeyHandle^ hKey, DWORD flags);

		// наследовать ключ
		public: KeyHandle^ DeriveKey(ALG_ID algID, HashHandle^ hHash, DWORD flags);
		// создать ключ
		public: KeyHandle^ GenerateKey(ALG_ID algID, DWORD flags);
		// импортировать ключ
		public: KeyHandle^ ImportKey(KeyHandle^ hImportKey, IntPtr ptrBlob, DWORD cbBlob, DWORD flags);  
	}; 
	///////////////////////////////////////////////////////////////////////////
	// Описатель контейнера
	///////////////////////////////////////////////////////////////////////////
	public ref class ContainerHandle : ContextHandle
	{
		// конструктор
		public: ContainerHandle(HCRYPTPROV hContainer, BOOL sspi) : ContextHandle(hContainer, sspi) {}
		 
		// тип провайдера
		public: property DWORD ProviderType { DWORD get() { return GetLong(PP_PROVTYPE, 0); }}	
		// имя провайдера 
		public: property String^ ProviderName { String^ get() { return GetString(PP_NAME, 0); }}
		// имя контейнера
		public: property String^ Name { String^ get() { return GetString(PP_CONTAINER, 0); }}

		// получить личный ключ
		public: KeyHandle^ GetUserKey(DWORD keyType);  

		// подписать хэш-значение
		public: array<BYTE>^ SignHash(DWORD keyType, HashHandle^ hHash, DWORD flags);  
	}; 
	///////////////////////////////////////////////////////////////////////////
	// Описатель хранилища
	///////////////////////////////////////////////////////////////////////////
	public ref class StoreHandle : ContextHandle
	{
		// открыть провайдер
		public: StoreHandle(DWORD type, String^ name, String^ reader, DWORD flags, BOOL sspi); 
		// конструктор
		public: StoreHandle(HCRYPTPROV hStore, BOOL sspi) : ContextHandle(hStore, sspi) {}
		 
		// тип провайдера
		public: property DWORD ProviderType { DWORD get() { return GetLong(PP_PROVTYPE, 0); }}	
		// имя провайдера
		public: property String^ ProviderName { String^ get() { return GetString(PP_NAME, 0); }}

		// перечислить объекты
		public: array<String^>^ Enumerate(DWORD paramID, DWORD flags); 
		// перечислить контейнеры
		public: array<String^>^ EnumerateContainers(DWORD flags); 

		// создать/открыть контейнер
		public: ContainerHandle^ AcquireContainer(String^ name, DWORD flags); 
		// удалить контейнер
		public: void DeleteContainer(String^ szName, DWORD flags); 
	}; 
	///////////////////////////////////////////////////////////////////////////
	// Описатель провайдера
	///////////////////////////////////////////////////////////////////////////
	public ref class ProviderHandle : StoreHandle
	{
		// открыть провайдер
		public: ProviderHandle(DWORD type, String^ name, DWORD flags, BOOL sspi); 
		// конструктор
		public: ProviderHandle(HCRYPTPROV hProvider, BOOL sspi) : StoreHandle(hProvider, sspi) {}
		 
		// тип провайдера
		public: property DWORD Type { DWORD get() { return ProviderType; }}	
		// имя провайдера
		public: property String^ Name { String^ get() { return ProviderName; }}

		// открыть хранилище
		public: StoreHandle^ AcquireStore(String^ name, DWORD flags); 
	}; 
}}}
