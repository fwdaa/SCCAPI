using System;
using System.Security;
using System.Security.Permissions;
using System.Runtime.InteropServices;

namespace Aladdin.PKCS11
{
	///////////////////////////////////////////////////////////////////////////
	// Модуль библиотеки PKCS11
	///////////////////////////////////////////////////////////////////////////
	public abstract class Module : RefObject
	{
		// конструктор
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
		public static Module Create(API nativeAPI) 
        {
            // получить функцию определения списка функций
            API.CK_GETFUNCTIONLIST getFunctionlist = nativeAPI.GetFunctionList(); 

            // проверить версию операционной системы
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                // вернуть требуемый модуль
                return new Module32(getFunctionlist); 
            }
            // инициализировать переменные
            bool is64 = false; bool initialized = false; 

            // получить адрес списка функций
            IntPtr ptrFunctionList; Exception.Check(getFunctionlist(out ptrFunctionList)); 

            // выполнить преобразование типа
            API64.CK_FUNCTION_LIST funcList = (API64.CK_FUNCTION_LIST)
                Marshal.PtrToStructure(ptrFunctionList, typeof(API64.CK_FUNCTION_LIST)
            ); 
            // выполнить инициализацию библиотеки
            uint code = (uint)funcList.C_Initialize(IntPtr.Zero); 

            // проверить инициализацию библиотеки
            if (code == API.CKR_CRYPTOKI_ALREADY_INITIALIZED) initialized = true; 
            
            // проверить отсутствие ошибок
            else { Exception.Check(code); initialized = false; }
            try { 
		        // получить информацию о модуле
		        API64.CK_INFO ckInfo; Exception.Check((uint)funcList.C_GetInfo(out ckInfo)); 

                // предположить размер целых цисел
                if (ckInfo.flags == 0) is64 = true; 
            }
            // освободить выделенные ресурсы
            finally { if (!initialized) funcList.C_Finalize(IntPtr.Zero); }

            // вернуть требуемый модуль
            if (is64) return new Module64(getFunctionlist); 
            
            // вернуть требуемый модуль
            else return new Module32(getFunctionlist); 
        }
		///////////////////////////////////////////////////////////////////////////
        // Общие фунциии
		///////////////////////////////////////////////////////////////////////////

		// информация о модуле
		public abstract Info Info { get; } 
        // размер целого числа
        public abstract int LongSize { get; } 

        // закодировать целое число
        public abstract byte[] EncodeLong(ulong value); 
        // раскодировать целое число
        public abstract ulong DecodeLong(byte[] encoded); 

		///////////////////////////////////////////////////////////////////////////
		// Создание атрибутов
		///////////////////////////////////////////////////////////////////////////
		public Aladdin.PKCS11.Attribute CreateAttribute(ulong type, byte value)
		{
			// создать атрибут
			return new Aladdin.PKCS11.Attribute(type, value); 
		}
		public Aladdin.PKCS11.Attribute CreateAttribute(ulong type, byte[] value)
		{
			// создать атрибут
			return new Aladdin.PKCS11.Attribute(type, value); 
		}
		public Aladdin.PKCS11.Attribute CreateAttribute(ulong type, string value)
		{
			// создать атрибут
			return new Aladdin.PKCS11.Attribute(type, value); 
		}
		public Aladdin.PKCS11.Attribute CreateAttribute(ulong type, ulong value)
        {
	        // создать атрибут
	        return new Aladdin.PKCS11.Attribute(type, EncodeLong(value)); 
        }
		///////////////////////////////////////////////////////////////////////////
		// Управление устройствами
		///////////////////////////////////////////////////////////////////////////

		// получить список считывателей
		public abstract ulong[] GetSlotList(bool tokenPresent); 

		// получить информацию о считывателе
		public abstract SlotInfo GetSlotInfo(ulong slotID); 

		// получить информацию о смарт-карте
		public abstract TokenInfo GetTokenInfo(ulong slotID); 

		// инициализировать смарт-карту
		public abstract void InitToken(ulong slotID, string pin, string label); 

		// закрыть все сеансы со смарт-картой
		public abstract void CloseAllSessions(ulong slotID); 

		///////////////////////////////////////////////////////////////////////////
		// Управление сеансами
		///////////////////////////////////////////////////////////////////////////

		// создать сеанс
		public abstract ulong OpenSession(ulong slotID, ulong flags); 

		// закрыть сеанс
		public abstract void CloseSession(ulong hSession); 

		// получить информацию о сеансе
		public abstract SessionInfo GetSessionInfo(ulong hSession); 

		// выполнить аутентификацию смарт-карты
		public abstract void Login(ulong hSession, ulong userType, string pin); 

		// отменить аутентификацию смарт-карты
		public abstract void Logout(ulong hSession); 

		// установить/изменить пин-код для CKU_USER от имени администратора
		public abstract void InitPIN(ulong hSession, string pin); 

		// изменить пин-код текущего пользователя
		public abstract void SetPIN(ulong hSession, string pinOld, string pinNew); 

		///////////////////////////////////////////////////////////////////////////
		// Управление алгоритмами
		///////////////////////////////////////////////////////////////////////////

		// получить список алгоритмов
		public abstract ulong[] GetAlgorithmList(ulong slotID); 

		// получить информацию об алгоритме
		public abstract MechanismInfo GetAlgorithmInfo(ulong slotID, ulong type); 

		///////////////////////////////////////////////////////////////////////////
		// Генерация случайных данных
		///////////////////////////////////////////////////////////////////////////

		// установить стартовое значение для генератора 
		public abstract void SeedRandom(ulong hSession, byte[] buffer, int offset, int length); 

		// сгенерировать случайные данные
		public abstract void GenerateRandom(ulong hSession, byte[] buffer, int offset, int length); 

		///////////////////////////////////////////////////////////////////////////
		// Управление объектами
		///////////////////////////////////////////////////////////////////////////

		// создать объект
		public abstract ulong CreateObject(ulong hSession, Attribute[] attributes); 

		// скопировать объект
		public abstract ulong CopyObject(ulong hSession, ulong hObject, Attribute[] attributes); 

		// закрыть объект
		public abstract void DestroyObject(ulong hSession, ulong hObject); 

		// найти объекты
		public abstract ulong[] FindObjects(ulong hSession, Attribute[] attributes); 

		// получить значение атрибутов
		public abstract Attribute[] GetAttributes(ulong hSession, ulong hObject, Attribute[] attributes); 

		// установить значение атрибута
		public abstract void SetAttributes(ulong hSession, ulong hObject, Attribute[] attributes); 

		// определить размер объекта на смарт-карте
		public abstract int GetObjectSize(ulong hSession, ulong hObject); 

		///////////////////////////////////////////////////////////////////////////
		// Управление ключами
		///////////////////////////////////////////////////////////////////////////

		// создать симметричный ключ
		public abstract ulong GenerateKey(ulong hSession, 
			Mechanism parameters, Attribute[] attributes
		);
		// создать пару ассиметричных ключей
		public abstract ulong[] GenerateKeyPair(
			ulong hSession, Mechanism parameters, 
			Attribute[] publicAttributes, Attribute[] privateAttributes
		);
		///////////////////////////////////////////////////////////////////////////
		// Хэширование данных
		///////////////////////////////////////////////////////////////////////////

		// инициализировать алгоритм хэширования
		public abstract void DigestInit(ulong hSession, Mechanism parameters);

		// захэшировать данные
		public abstract void DigestUpdate(ulong hSession, 
			byte[] data, int dataOff, int dataLen
		);
		// захэшировать значение ключа
		public abstract void DigestKey(ulong hSession, ulong hKey);

		// получить хэш-значение
		public abstract int DigestFinal(ulong hSession, byte[] buf, int bufOff);

		///////////////////////////////////////////////////////////////////////////
		// Выработка имитовставки и подписи данных
		///////////////////////////////////////////////////////////////////////////

		// инициализировать алгоритм имитовставки или подписи данных
		public abstract void SignInit(ulong hSession, 
			Mechanism parameters, ulong hKey
		);
		// обработать данные
		public abstract void SignUpdate(ulong hSession, 
			byte[] data, int dataOff, int dataLen
		);
		// получить имитовставку или подпись данных
		public abstract int SignFinal(ulong hSession, byte[] buff, int bufOff);

		// получить имитовставку или подпись данных
		public abstract byte[] Sign(ulong hSession, 
			byte[] data, int dataOff, int dataLen
		);
		///////////////////////////////////////////////////////////////////////////
		// Проверка имитовставки и подписи данных
		///////////////////////////////////////////////////////////////////////////

		// инициализировать алгоритм имитовставки или проверки подписи
		public abstract void VerifyInit(ulong hSession, 
			Mechanism parameters, ulong hKey
		);
		// обработать данные
		public abstract void VerifyUpdate(ulong hSession, 
			byte[] data, int dataOff, int dataLen
		);  
		// проверить имитовставку или подпись данных
		public abstract void VerifyFinal(ulong hSession, byte[] signature);

		// проверить имитовставку или подпись данных
		public abstract void Verify(ulong hSession, 
            byte[] data, int dataOff, int dataLen, byte[] signature
		);
		///////////////////////////////////////////////////////////////////////////
		// Шифрование данных
		///////////////////////////////////////////////////////////////////////////

		// инициализировать алгоритм зашифрования
		public abstract void EncryptInit(ulong hSession, 
            Mechanism parameters, ulong hKey
        );
		// зашифровать данные
		public abstract int EncryptUpdate(ulong hSession, byte[] data, 
			int dataOff, int dataLen, byte[] buffer, int bufferOff
		);
		// завершить зашифрование данных
		public abstract int EncryptFinal(ulong hSession, 
			byte[] buffer, int bufferOff
		);
		// зашифровать данные
		public abstract byte[] Encrypt(ulong hSession, 
            byte[] data, int dataOff, int dataLen
		);
		// инициализировать алгоритм расшифрования
		public abstract void DecryptInit(ulong hSession, 
			Mechanism parameters, ulong hKey
		);
		// расшифровать данные
		public abstract int DecryptUpdate(ulong hSession, 
            byte[] data, int dataOff, int dataLen, byte[] buffer, int bufferOff
		);
		// завершить расшифрование данных
		public abstract int DecryptFinal(ulong hSession, 
			byte[] buffer, int bufferOff
		);
		// расшифровать данные
		public abstract byte[] Decrypt(ulong hSession, 
            byte[] data, int dataOff, int dataLen
		);
		///////////////////////////////////////////////////////////////////////////
		// Шифрование ключа
		///////////////////////////////////////////////////////////////////////////

		// зашифровать ключ
		public abstract byte[] WrapKey(ulong hSession, 
            Mechanism parameters, ulong hWrapKey, ulong hKey
		);
		// расшифровать ключ
		public abstract ulong UnwrapKey(ulong hSession, 
			Mechanism parameters, ulong hWrapKey, 
            byte[] data, Attribute[] attributes
		);
		///////////////////////////////////////////////////////////////////////////
		// Наследование ключа
		///////////////////////////////////////////////////////////////////////////
		public abstract ulong DeriveKey(ulong hSession, 
            Mechanism parameters, ulong hBaseKey, Attribute[] attributes
		);
	};
}
