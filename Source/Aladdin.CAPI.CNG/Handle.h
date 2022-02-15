#pragma once

namespace Aladdin { namespace CAPI { namespace CNG 
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
		protected: Handle() : SafeHandle(IntPtr::Zero, true) {}

		// признак некорректного описателя
		public: virtual property bool IsInvalid 
		{ 
			// признак некорректного описателя
			[SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
			bool get() override { return handle == IntPtr::Zero; }
		}
		// деструктор
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override
        {
			// отменить вызов деструктора
			GC::SuppressFinalize(this); return true; 
        }
		// получить параметр
		public: virtual DWORD GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) = 0; 
		// получить параметр
		public: virtual DWORD GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) = 0; 
		// установить параметр
		public: virtual void SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) = 0; 

		// получить параметр алгоритма
		public: array<BYTE>^ GetSafeParam(String^ param, DWORD flags); 
		// получить параметр алгоритма
		public: array<BYTE>^ GetParam(String^ param, DWORD flags); 
		// получить параметр алгоритма
		public: String^ GetString(String^ param, DWORD flags); 
		// получить параметр алгоритма
		public: DWORD GetLong(String^ param, DWORD flags); 

		// установить параметр алгоритма
		public: void SetParam(String^ param, array<BYTE>^ value, DWORD flags); 
		// установить параметр алгоритма
		public: void SetString(String^ param, String^ value, DWORD flags); 
		// установить параметр алгоритма
		public: void SetLong(String^ param, DWORD value, DWORD flags); 
	};
	///////////////////////////////////////////////////////////////////////////
	// Описатель алгоритма хэширования
	///////////////////////////////////////////////////////////////////////////
	public ref class BHashHandle : Handle
	{
		// память для объекта
		private: IntPtr	ptrObj;	private: int cbObj;

		// конструктор
		public: BHashHandle(BCRYPT_HASH_HANDLE hObject, IntPtr ptrObj, int cbObj) 
		{ 
			// установить описатель
			SetHandle((IntPtr)(PVOID)hObject); this->ptrObj = ptrObj; this->cbObj = cbObj;
		}
		// деструктор
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override
		{
			// вызвать базовую функцию
            if (!Handle::ReleaseHandle()) return false;  
			
			// освободить описатель объекта 
			bool success = SUCCEEDED(::BCryptDestroyHash(Value)); 
			
			// освободить память объекта
			if (ptrObj != IntPtr::Zero) Marshal::FreeHGlobal(ptrObj); return success; 
		} 
		// описатель алгоритма хэширования
		public: property BCRYPT_HASH_HANDLE Value 
		{ 
			// описатель алгоритма хэширования
			BCRYPT_HASH_HANDLE get() { return (BCRYPT_HASH_HANDLE)handle.ToPointer(); }
		} 
		// получить параметр
		public: virtual DWORD GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// получить параметр
		public: virtual DWORD GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// установить параметр
		public: virtual void SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 

		// создать копию алгоритма хэширования
		public: BHashHandle^ Duplicate(DWORD flags); 

		// захэшировать данные 
		public: void HashData(array<BYTE>^ data, int dataOff, int dataLen, DWORD flags);

		// получить хэш-значение
		public: array<BYTE>^ FinishHash(DWORD flags); 
	};
	///////////////////////////////////////////////////////////////////////////
	// Описатель разделенного секрета
	///////////////////////////////////////////////////////////////////////////
	public ref class BSecretHandle : Handle
	{
		// конструктор
		public: BSecretHandle(BCRYPT_SECRET_HANDLE hObject) 
		{ 
			// установить описатель
			SetHandle((IntPtr)(PVOID)hObject); 
		}
		// деструктор
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override
		{ 
			// вызвать базовую функцию
            if (!Handle::ReleaseHandle()) return false; 
			
			// освободить описатель объекта 
			return SUCCEEDED(::BCryptDestroySecret(Value)); 
		} 
		// описатель разделенного секрета
		public: property BCRYPT_SECRET_HANDLE Value 
		{ 
			// описатель разделенного секрета
			BCRYPT_SECRET_HANDLE get() { return (BCRYPT_SECRET_HANDLE)handle.ToPointer(); }
		} 
		// получить параметр
		public: virtual DWORD GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// получить параметр
		public: virtual DWORD GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// установить параметр
		public: virtual void SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 

		// наследовать ключ
		public: array<BYTE>^ DeriveKey(String^ nameKDF, DWORD keySize, IntPtr params, DWORD flags); 
	};
	///////////////////////////////////////////////////////////////////////////
	// Описатель разделенного секрета
	///////////////////////////////////////////////////////////////////////////
	public ref class NSecretHandle : Handle
	{
		// конструктор
		public: NSecretHandle(NCRYPT_SECRET_HANDLE hObject) 
		{ 
			// установить описатель
			SetHandle((IntPtr)(PVOID)hObject); 
		}
		// деструктор
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override
		{ 
            // вызвать базовую функцию
            if (!Handle::ReleaseHandle()) return false; 
			
			// освободить объект
			return ::NCryptFreeObject(Value) == ERROR_SUCCESS;
		} 
		// описатель разделенного секрета
		public: property NCRYPT_SECRET_HANDLE Value 
		{ 
			// описатель разделенного секрета
			NCRYPT_SECRET_HANDLE get() { return (NCRYPT_SECRET_HANDLE)handle.ToPointer(); }
		} 
		// получить параметр
		public: virtual DWORD GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// получить параметр
		public: virtual DWORD GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// установить параметр
		public: virtual void SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 

		// наследовать ключ
		public: array<BYTE>^ DeriveKey(String^ nameKDF, DWORD keySize, IntPtr params, DWORD flags); 
	};
	///////////////////////////////////////////////////////////////////////////
	// Описатель ключа
	///////////////////////////////////////////////////////////////////////////
	public ref class BKeyHandle : Handle
	{
		// память для объекта
		private: IntPtr	ptrObj;	private: int cbObj;

		// преобразовать открытый ключ
		public: static BKeyHandle^ ImportPublicKeyInfo(
            ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo, DWORD flags
        ); 
		// конструктор
		public: BKeyHandle(BCRYPT_KEY_HANDLE hObject, IntPtr ptrObj, int cbObj)
		{ 
			// установить описатель
			SetHandle((IntPtr)(PVOID)hObject); this->ptrObj = ptrObj; this->cbObj = cbObj;
		}
		// деструктор
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override
		{ 
			// вызвать базовую функцию
            if (!Handle::ReleaseHandle()) return false; 
			
			// освободить объект
			bool success = SUCCEEDED(::BCryptDestroyKey(Value));
 
			// освободить память объекта
			if (ptrObj != IntPtr::Zero) Marshal::FreeHGlobal(ptrObj); return success; 
		} 
		// описатель ключа
		public: property BCRYPT_KEY_HANDLE Value 
		{ 
			// описатель ключа
			BCRYPT_KEY_HANDLE get() { return (BCRYPT_KEY_HANDLE)handle.ToPointer(); }
		}   
		// получить параметр
		public: virtual DWORD GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// получить параметр
		public: virtual DWORD GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// установить параметр
		public: virtual void SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 

		// создать копию ключа
		public: BKeyHandle^ Duplicate(DWORD flags);

		// экспортировать ключ
		public: DWORD Export(BKeyHandle^ hExportKey, String^ blobType, 
			DWORD flags, IntPtr ptrBlob, DWORD cbBlob
		); 
#if _WIN32_WINNT >= 0x0602
		// наследовать ключ
		public: array<BYTE>^ DeriveKey(DWORD keySize, IntPtr params, DWORD flags); 
#endif
		// согласовать ключ
		public: BSecretHandle^ AgreementSecret(BKeyHandle^ hPublicKey, DWORD flags); 

		// зашифровать данные 
		public: DWORD Encrypt(array<BYTE>^ iv, array<BYTE>^ data, DWORD dataOff, 
			DWORD dataLen, DWORD flags, array<BYTE>^ buffer, DWORD bufferOff 
		); 
		// расшифровать данные 
		public: DWORD Decrypt(array<BYTE>^ iv, array<BYTE>^ data, DWORD dataOff, 
			DWORD dataLen, DWORD flags, array<BYTE>^ buffer, DWORD bufferOff 
		);
		// зашифровать данные 
		public: array<BYTE>^ Encrypt(IntPtr padding, array<BYTE>^ data, DWORD flags);
		// расшифровать данные 
		public: array<BYTE>^ Decrypt(IntPtr padding, array<BYTE>^ data, DWORD flags);

		// подписать хэш-значение
		public: array<BYTE>^ SignHash(IntPtr padding, array<BYTE>^ hash, DWORD flags);  
		// проверить подпись хэш-значения
		public: void VerifySignature(IntPtr padding, array<BYTE>^ hash, array<BYTE>^ signature, DWORD flags);  
	}; 
	///////////////////////////////////////////////////////////////////////////
	// Описатель ключа
	///////////////////////////////////////////////////////////////////////////
	public ref class NKeyHandle : Handle
	{
		// конструктор
		public: NKeyHandle(NCRYPT_KEY_HANDLE hObject) 
		{
			// установить описатель
			SetHandle((IntPtr)(PVOID)hObject); 
		}
        // завершить создание ключа
        public: void Finalize(DWORD flags);   

		// деструктор
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override
		{ 
			// вызвать базовую функцию
            if (!Handle::ReleaseHandle()) return false; 
			
			// освободить описатель объекта 
			return ::NCryptFreeObject(Value) == ERROR_SUCCESS;
		} 
		// описатель ключа
		public: property NCRYPT_KEY_HANDLE Value 
		{ 
			// описатель ключа
			NCRYPT_KEY_HANDLE get() { return (NCRYPT_KEY_HANDLE)handle.ToPointer(); }
		}   
		// получить параметр
		public: virtual DWORD GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// получить параметр
		public: virtual DWORD GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// установить параметр
		public: virtual void SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 

		// экспортировать ключ
		public: DWORD Export(NKeyHandle^ hExportKey, String^ blobType, 
			DWORD flags, IntPtr ptrBlob, DWORD cbBlob
		); 
#if _WIN32_WINNT >= 0x0602
		// наследовать ключ
		public: array<BYTE>^ DeriveKey(DWORD keySize, IntPtr params, DWORD flags); 
#endif
		// согласовать ключ
		public: NSecretHandle^ AgreementSecret(NKeyHandle^ hPublicKey, DWORD flags); 

		// зашифровать данные 
		public: array<BYTE>^ Encrypt(IntPtr padding, array<BYTE>^ data, DWORD flags);
		// расшифровать данные 
		public: array<BYTE>^ Decrypt(IntPtr padding, array<BYTE>^ data, DWORD flags);

		// подписать хэш-значение
		public: array<BYTE>^ SignHash(IntPtr padding, array<BYTE>^ hash, DWORD flags);  
		// проверить подпись хэш-значения
		public: void VerifySignature(IntPtr padding, array<BYTE>^ hash, array<BYTE>^ signature, DWORD flags);  
	}; 
	///////////////////////////////////////////////////////////////////////////
	// Описатель провайдера алгоритма
	///////////////////////////////////////////////////////////////////////////
	public ref class BProviderHandle : Handle
	{
		// конструктор
		public: BProviderHandle(String^ provider, String^ alg, DWORD flags); 

		// конструктор
		public: BProviderHandle(BCRYPT_ALG_HANDLE hObject) 
		{ 	
			// установить описатель
			SetHandle((IntPtr)(PVOID)hObject); 
		} 
		// деструктор
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override
		{ 
			// вызвать базовую функцию
            if (!Handle::ReleaseHandle()) return false;  
			
			// освободить описатель объекта 
			return SUCCEEDED(::BCryptCloseAlgorithmProvider(Value, 0));
		}
		// описатель провайдера алгоритма
		public: property BCRYPT_ALG_HANDLE Value 
		{ 
			// описатель провайдера алгоритма
			BCRYPT_ALG_HANDLE get() { return (BCRYPT_ALG_HANDLE)handle.ToPointer(); }
		}   
		// получить параметр
		public: virtual DWORD GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// получить параметр
		public: virtual DWORD GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// установить параметр
		public: virtual void SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 

		// сгенерировать случайные данные
		public: void Generate(array<BYTE>^ buffer, 
			DWORD bufferOff, DWORD bufferLen, DWORD flags
		); 
		// создать алгоритм хэширования
		public: BHashHandle^ CreateHash(array<BYTE>^ key, DWORD flags);

		// создать ключ
		public: BKeyHandle^ GenerateKey(DWORD flags);
		// импортировать ключ
		public: BKeyHandle^ ImportKey(BKeyHandle^ hImportKey, 
			String^ blobType, IntPtr ptrData, DWORD cbData, DWORD flags
		);
		// начать создание пары ключей
		public: BKeyHandle^ CreateKeyPair(DWORD length, DWORD flags);
		// завершить создание пары ключей
		public: void FinalizeKeyPair(BKeyHandle^ hKeyPair, DWORD flags);

		// импортировать ключевую пару
		public: BKeyHandle^ ImportKeyPair(BKeyHandle^ hImportKey, 
			String^ blobType, IntPtr ptrData, DWORD cbData, DWORD flags
		);  
	}; 
	///////////////////////////////////////////////////////////////////////////
	// Описатель провайдера
	///////////////////////////////////////////////////////////////////////////
	public ref class NProviderHandle : Handle
	{
		// конструктор
		public: NProviderHandle(String^ name, DWORD flags); 

		// конструктор
		public: NProviderHandle(NCRYPT_PROV_HANDLE hObject) 
		{ 	
			// установить описатель
			SetHandle((IntPtr)(PVOID)hObject); 
		} 
		// деструктор
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override
		{ 
			// вызвать базовую функцию
            if (!Handle::ReleaseHandle()) return false;  
			
			// освободить описатель объекта 
			return ::NCryptFreeObject(Value) == ERROR_SUCCESS;
		} 
		// описатель провайдера алгоритма
		public: property NCRYPT_PROV_HANDLE Value 
		{ 
			// описатель провайдера алгоритма
			NCRYPT_PROV_HANDLE get() { return (NCRYPT_PROV_HANDLE)handle.ToPointer(); }
		}   
		// определить имя провайдера
		public: property String^ Name { String^ get() 
		{ 
			// определить имя провайдера
			return GetString(NCRYPT_NAME_PROPERTY, 0);  
		}} 
		// получить параметр
		public: virtual DWORD GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// получить параметр
		public: virtual DWORD GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// установить параметр
		public: virtual void SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 

		// перечислить алгоритмы
		public: array<String^>^ EnumerateAlgorithms(DWORD type, DWORD flags); 
		// перечислить ключи
		public: array<String^>^ EnumerateKeys(String^ scope, DWORD flags); 

		// начать создание пары ключей
		public: NKeyHandle^ StartCreateKey(String^ name, String^ algID, 
			DWORD keyType, DWORD flags
		);
		// получить пару ключей
		public: NKeyHandle^ OpenKey(String^ name, DWORD keyType, DWORD flags);
		// удалить пару ключей
		public: static void DeleteKey(NKeyHandle^ hKeyPair, DWORD flags);

		// начать импортировать пару ключей
		public: NKeyHandle^ StartImportKeyPair(String^ name, 
            NKeyHandle^ hImportKey, String^ blobType, IntPtr ptrBlob, 
            DWORD cbBlob, DWORD flags
		);
		// импортировать открытый ключ
		public: NKeyHandle^ ImportPublicKey(
            String^ blobType, IntPtr ptrBlob, DWORD cbBlob, DWORD flags
        );  
	}; 
}}}
