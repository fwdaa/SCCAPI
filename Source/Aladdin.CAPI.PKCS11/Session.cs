using System;
using System.Collections.Generic;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////////
    // Сеанс взаимодействия с устройством
    ///////////////////////////////////////////////////////////////////////////////
    public sealed class Session : RefObject
    {
	    private Module	module;		// модуль библиотеки PKCS11
	    private UInt64 	slotID;		// идентификатор считывателя
	    private UInt64  hSession;	// описатель сеанса

	    // конструктор
	    public Session(Module module, UInt64 slotID, UInt64 mode)
	    {
		    // сохранить переданные параметры
		    this.module = module; this.slotID = slotID;	
			
		    // создать новый сеанс
		    hSession = module.OpenSession(slotID, mode);
	    }
	    // деструктор
	    protected override void OnDispose() 
        { 
            // закрыть сеанс
            module.CloseSession(hSession); base.OnDispose(); 
        }
	    public Module Module { get { return module;   }}
	    public UInt64 SlotID { get { return slotID;   }}
	    public UInt64 Handle { get { return hSession; }}

	    ///////////////////////////////////////////////////////////////////////////
	    // Аутентификация пользователя
	    ///////////////////////////////////////////////////////////////////////////
	    public SessionInfo GetSessionInfo() 
	    { 
		    // получить информацию о сеансе
		    return module.GetSessionInfo(hSession); 
	    }
	    // установить пин-код
	    public void Login(ulong userType, string password) 
        {
		    // установить пин-код
		    module.Login(hSession, userType, password); 
	    }
	    // сбросить аутентификацию
	    public void Logout() { module.Logout(hSession); }

	    // установить/изменить пин-код для CKU_USER от имени администратора
	    public void SetUserPassword(string password)
	    {
		    // установить/изменить пин-код
		    module.InitPIN(hSession, password); 
	    }
	    // изменить пин-код текущего пользователя
	    public void ChangePassword(string passwordOld, string passwordNew)
	    {
		    // изменить пин-код текущего пользователя
		    module.SetPIN(hSession, passwordOld, passwordNew); 
	    }
	    ///////////////////////////////////////////////////////////////////////////
	    // Генерация случайных данных
	    ///////////////////////////////////////////////////////////////////////////

	    // установить стартовое значение для генератора 
	    public void SeedRandom(byte[] buffer, int offset, int length)
	    {
		    // установить стартовое значение для генератора 
		    module.SeedRandom(hSession, buffer, offset, length); 
	    }
	    // сгенерировать случайные данные
	    public void GenerateRandom(byte[] buffer, int offset, int length)
	    {
		    // сгенерировать случайные данные
		    module.GenerateRandom(hSession, buffer, offset, length); 
	    }
	    ///////////////////////////////////////////////////////////////////////////
	    // Управление ключами
	    ///////////////////////////////////////////////////////////////////////////

	    // создать симметричный ключ
	    public SessionObject GenerateKey(Mechanism parameters, Attribute[] attributes)
        {
	        // создать симметричный ключ
	        UInt64 hObject = module.GenerateKey(hSession, parameters, attributes);
	 
	        // вернуть созданный объект
	        return new SessionObject(this, hObject); 
        }
	    // создать пару ассиметричных ключей
	    public SessionObject[] GenerateKeyPair(Mechanism parameters, 
            Attribute[] requiredPublicAttributes, Attribute[] requiredPrivateAttributes, 
			Attribute[] optionalPublicAttributes, Attribute[] optionalPrivateAttributes)
        {
	        // проверить наличие атрибутов
	        if (optionalPublicAttributes  == null) optionalPublicAttributes  = new Attribute[0]; 
	        if (optionalPrivateAttributes == null) optionalPrivateAttributes = new Attribute[0]; 

			// создать список атрибутов
			List<Attribute> publicAttributes  = new List<Attribute>(requiredPublicAttributes ); 
			List<Attribute> privateAttributes = new List<Attribute>(requiredPrivateAttributes); 

			// указать необязательные атрибуты
			publicAttributes .AddRange(optionalPublicAttributes ); 
			privateAttributes.AddRange(optionalPrivateAttributes); 

	        // выделить память для результата
	        SessionObject[] objects = new SessionObject[2]; 
			try {  	
				// создать пару ассиметричных ключей
				UInt64[] hObjects = module.GenerateKeyPair(hSession, parameters, 
					publicAttributes.ToArray(), privateAttributes.ToArray()
				); 
				// вернуть созданные объекты
				objects[0] = new SessionObject(this, hObjects[0]); 
				objects[1] = new SessionObject(this, hObjects[1]); return objects; 
			}
			// при возникновении ошибки
			catch (Aladdin.PKCS11.Exception e) 
			{
				// проверить код ошибки
				if (e.ErrorCode != API.CKR_ATTRIBUTE_TYPE_INVALID) throw; 

				// проверить наличие необязательных атрибутов
				if (optionalPublicAttributes .Length == 0 && 
					optionalPrivateAttributes.Length == 0) throw; 

				// создать пару ассиметричных ключей
				UInt64[] hObjects = module.GenerateKeyPair(hSession, parameters, 
					requiredPublicAttributes, requiredPrivateAttributes
				); 
				// вернуть созданные объекты
				objects[0] = new SessionObject(this, hObjects[0]); 
				objects[1] = new SessionObject(this, hObjects[1]); return objects; 
			}
        }
		// сгенерировать пару ключей
		public SessionObject[] GenerateKeyPair(Mechanism parameters, KeyUsage keyUsage, 
            Attribute[] publicAttributes, Attribute[] privateAttributes)
        {
	        // создать списки атрибутов
	        List<Attribute> pubAttributes  = new List<Attribute>(publicAttributes ); 
	        List<Attribute> privAttributes = new List<Attribute>(privateAttributes); 

	        // определить значения атрибутов
	        if (KeyUsage.None != (keyUsage & (KeyUsage.DigitalSignature | 
		        KeyUsage.CertificateSignature | KeyUsage.CrlSignature | KeyUsage.NonRepudiation)))
            {
	            // указать значения атрибутов
	            privAttributes.Add(new Attribute(API.CKA_SIGN  , API.CK_TRUE));  
	            pubAttributes .Add(new Attribute(API.CKA_VERIFY, API.CK_TRUE));  
            }
	        // определить значения атрибутов
	        if (KeyUsage.None != (keyUsage &  KeyUsage.KeyEncipherment))
            {
	            // указать значения атрибутов
	            pubAttributes .Add(new Attribute(API.CKA_WRAP  , API.CK_TRUE));  
	            privAttributes.Add(new Attribute(API.CKA_UNWRAP, API.CK_TRUE));  
            }
	        // определить значения атрибутов
	        if (KeyUsage.None != (keyUsage &  KeyUsage.KeyAgreement))
            {
	            // указать значения атрибутов
	            privAttributes.Add(new Attribute(API.CKA_DERIVE, API.CK_TRUE));  
	            pubAttributes .Add(new Attribute(API.CKA_DERIVE, API.CK_TRUE));  
            }
			// создать необязательные атрибуты
			List<Attribute> optionalPubAttributes  = new List<Attribute>(); 
			List<Attribute> optionalPrivAttributes = new List<Attribute>(); 

            // определить значения атрибутов
            if (KeyUsage.None != (keyUsage &  KeyUsage.DataEncipherment))
            {  
                // указать значения атрибутов
                optionalPubAttributes .Add(new Attribute(API.CKA_ENCRYPT, API.CK_TRUE));  
                optionalPrivAttributes.Add(new Attribute(API.CKA_DECRYPT, API.CK_TRUE));  
			}
            // сгенерировать пару ключей
            return GenerateKeyPair(parameters, pubAttributes.ToArray(), privAttributes.ToArray(), 
				optionalPubAttributes.ToArray(), optionalPrivAttributes.ToArray()
			);
        }
	    ///////////////////////////////////////////////////////////////////////////
	    // Управление объектами
	    ///////////////////////////////////////////////////////////////////////////

        // создать пару ключей
		public SessionObject[] CreateKeyPair(KeyUsage keyUsage, 
            Attribute[] publicAttributes, Attribute[] privateAttributes)
        {
	        // создать списки атрибутов
	        List<Attribute> pubAttributes  = new List<Attribute>(publicAttributes ); 
	        List<Attribute> privAttributes = new List<Attribute>(privateAttributes); 

	        // определить значения атрибутов
	        if (KeyUsage.None != (keyUsage & (KeyUsage.DigitalSignature | 
		        KeyUsage.CertificateSignature | KeyUsage.CrlSignature | KeyUsage.NonRepudiation)))
            {
	            // указать значения атрибутов
	            privAttributes.Add(new Attribute(API.CKA_SIGN   , API.CK_TRUE));  
	            pubAttributes .Add(new Attribute(API.CKA_VERIFY , API.CK_TRUE));  
            }
	        // определить значения атрибутов
	        if (KeyUsage.None != (keyUsage &  KeyUsage.KeyEncipherment))
            {
	            // указать значения атрибутов
	            pubAttributes .Add(new Attribute(API.CKA_WRAP  , API.CK_TRUE));  
	            privAttributes.Add(new Attribute(API.CKA_UNWRAP, API.CK_TRUE));  
            }
	        // определить значения атрибутов
	        if (KeyUsage.None != (keyUsage &  KeyUsage.KeyAgreement))
            {
	            // указать значения атрибутов
	            privAttributes.Add(new Attribute(API.CKA_DERIVE, API.CK_TRUE));  
	            pubAttributes .Add(new Attribute(API.CKA_DERIVE, API.CK_TRUE));  
            }
            // сохранить списки атрибутов
            publicAttributes  = pubAttributes.ToArray(); 
			privateAttributes = privAttributes.ToArray();

			// создать необязательные атрибуты
			List<Attribute> optionalPubAttributes  = new List<Attribute>(); 
			List<Attribute> optionalPrivAttributes = new List<Attribute>(); 

            // определить значения атрибутов
            if (KeyUsage.None != (keyUsage &  KeyUsage.DataEncipherment))
            {  
                // указать значения атрибутов
                optionalPubAttributes .Add(new Attribute(API.CKA_ENCRYPT, API.CK_TRUE));  
                optionalPrivAttributes.Add(new Attribute(API.CKA_DECRYPT, API.CK_TRUE));  
			}
            // выделить буфер требуемого размера
            SessionObject[] objs = new SessionObject[2]; 

            // сохранить открытый ключ на смарт-карту
            objs[0] = CreateObject(publicAttributes, optionalPubAttributes.ToArray()); 
            try { 
                // сохранить личный ключ на смарт-карту
                objs[1] = CreateObject(privateAttributes, optionalPrivAttributes.ToArray()); 
            }
            // при ошибке удалить личный ключ
            catch { DestroyObject(objs[0]); throw; } return objs; 
        }
	    // создать объект
	    public SessionObject CreateObject(
			Attribute[] requiredAttributes, Attribute[] optionalAttributes)
        {
	        // проверить наличие атрибутов
	        if (requiredAttributes == null) requiredAttributes = new Attribute[0]; 
	        if (optionalAttributes == null) optionalAttributes = new Attribute[0]; 

	        // для всех атрибутов 
	        foreach (Attribute attribute in requiredAttributes)
	        {
		        // проверить наличие значения
		        if (attribute.Value != null) continue; 
				
		        // при ошибке выбросить исключение
		        throw new Aladdin.PKCS11.Exception(API.CKR_KEY_UNEXTRACTABLE);
	        }
	        // для всех атрибутов 
	        foreach (Attribute attribute in optionalAttributes)
	        {
		        // проверить наличие значения
		        if (attribute.Value != null) continue; 
				
		        // при ошибке выбросить исключение
		        throw new Aladdin.PKCS11.Exception(API.CKR_KEY_UNEXTRACTABLE);
	        }
			// создать список атрибутов
			List<Attribute> attributes = new List<Attribute>(requiredAttributes); 

			// указать необязательные атрибуты
			attributes.AddRange(optionalAttributes); 
			try {  
				// создать объект с указанными атрибутами
				UInt64 hObject = module.CreateObject(hSession, attributes.ToArray());  
	 
				// вернуть созданный объект
				return new SessionObject(this, hObject); 
			}
			// при возникновении ошибки
			catch (Aladdin.PKCS11.Exception e) 
			{
				// проверить код ошибки
				if (e.ErrorCode != API.CKR_ATTRIBUTE_TYPE_INVALID) throw; 

				// проверить наличие необязательных атрибутов
				if (optionalAttributes.Length == 0) throw; 

				// создать объект с указанными атрибутами
				UInt64 hObject = module.CreateObject(hSession, requiredAttributes);  
	 
				// вернуть созданный объект
				return new SessionObject(this, hObject); 
			}
        }
	    // найти объекты с указанными атрибутами
	    public SessionObject[] FindObjects(Attribute[] attributes)
        {
	        // найти объекты с указанными атрибутами
	        UInt64[] handles = module.FindObjects(hSession, attributes);

	        // выделить память для объектов
	        SessionObject[] objects = new SessionObject[handles.Length]; 

	        // для каждого найденного объекта
	        for (int i = 0; i < handles.Length; i++)
	        {
		        // создать объект по описателю
		        objects[i] = new SessionObject(this, handles[i]);
	        }
	        return objects;
        }
	    // найти объект с указанными атрибутами
	    public SessionObject FindObject(Attribute[] attributes)
        {
	        // найти объект на устройстве
	        UInt64[] handles = module.FindObjects(hSession, attributes);

	        // проверить корректность поиска
	        if (handles.Length == 0) throw new Aladdin.PKCS11.Exception(API.CKR_TEMPLATE_INCONSISTENT); 

	        // проверить однозначность поиска
	        if (handles.Length != 1) throw new Aladdin.PKCS11.Exception(API.CKR_TEMPLATE_INCOMPLETE); 

	        // вернуть найденный объект
	        return new SessionObject(this, handles[0]); 
        }
	    // создать объект на токене
	    public SessionObject CreateTokenObject(string label, 
			Attribute[] requiredAttributes, Attribute[] optionalAttributes)
        {
	        // выделить память для атрибутов
	        Attribute[] attrs = new Attribute[] {

	            // указать признак нахождения на устройстве
	            new Attribute(API.CKA_TOKEN, API.CK_TRUE), 

	            // указать имя объекта
	            new Attribute(API.CKA_LABEL, label)
            }; 
	        // создать объект на токене
	        return CreateObject(
				Attribute.Join(requiredAttributes, attrs), optionalAttributes
			); 
        }
	    // найти объекты с указанными атрибутами
	    public SessionObject[] FindTokenObjects(string label, Attribute[] attributes)
        {
	        // выделить память для атрибутов поиска
	        Attribute[] attrs = new Attribute[] {

	            // указать признак нахождения на устройстве
	            new Attribute(API.CKA_TOKEN, API.CK_TRUE), 

	            // указать имя объекта
	            new Attribute(API.CKA_LABEL, label)
            }; 
	        // найти объекты на токене
	        SessionObject[] objs = FindObjects(Attribute.Join(attributes, attrs)); 

	        // проверить наличие объектов
	        if (objs.Length != 0) return objs;
            try {  
	            // проверить формат имени контейнера
	            byte[] id = Arrays.FromHexString(label); 

	            // указать для поиска имя объекта
	            attrs[1] = new Attribute(API.CKA_ID, id);
            }
            // обработать возможную ошибку
            catch { return objs; }

	        // найти объекты на токене
	        return FindObjects(Attribute.Join(attributes, attrs)); 
        } 
	    // найти объект на смарт-карте с указанными атрибутами
	    public SessionObject FindTokenObject(string label, Attribute[] attributes)
        {
	        // выделить память для атрибутов
	        Attribute[] attrs = new Attribute[] {

	            // указать признак нахождения на устройстве
	            new Attribute(API.CKA_TOKEN, API.CK_TRUE), 

	            // указать имя объекта
	            new Attribute(API.CKA_LABEL, label)
            }; 
	        // найти объекты на токене
	        SessionObject[] objs = FindObjects(Attribute.Join(attributes, attrs)); 

	        // проверить однозначность поиска
	        if (objs.Length == 1) return objs[0]; if (objs.Length > 1) 
	        {
		        // при ошибке выбросить исключение
		        throw new Aladdin.PKCS11.Exception(API.CKR_TEMPLATE_INCOMPLETE); 
	        }
            try {  
	            // проверить формат имени контейнера
	            byte[] id = Arrays.FromHexString(label); 

	            // указать для поиска имя объекта
	            attrs[1] = new Attribute(API.CKA_ID, id);
            }
            // обработать возможную ошибку
            catch { return null; }

	        // найти объект на токене
	        objs = FindObjects(Attribute.Join(attributes, attrs)); 

	        // проверить однозначность поиска
	        if (objs.Length == 1) return objs[0]; if (objs.Length > 1) 
	        {
		        // при ошибке выбросить исключение
		        throw new Aladdin.PKCS11.Exception(API.CKR_TEMPLATE_INCOMPLETE); 
	        }
	        return null; 
        }
	    // удалить объект
	    public void DestroyObject(SessionObject obj)
        {
	        // удалить объект
	        module.DestroyObject(hSession, obj.Handle); 
        }
	    ///////////////////////////////////////////////////////////////////////////
	    // Хэширование данных
	    ///////////////////////////////////////////////////////////////////////////

	    // инициализировать алгоритм хэширования
	    public void DigestInit(Mechanism parameters)
	    {
		    // инициализировать алгоритм хэширования
		    module.DigestInit(hSession, parameters); 
	    }
	    // захэшировать данные
	    public void DigestUpdate(byte[] data, int dataOff, int dataLen)
	    {
		    // захэшировать данные
		    module.DigestUpdate(hSession, data, dataOff, dataLen); 
	    }
	    // захэшировать значение ключа
	    public void DigestKey(UInt64 hKey)
	    {
		    // захэшировать значение ключа
		    module.DigestKey(hSession, hKey); 
	    }
	    // получить хэш-значение
	    public int DigestFinal(byte[] buf, int bufOff)
	    {
		    // получить хэш-значение
		    return module.DigestFinal(hSession, buf, bufOff); 
	    }
	    ///////////////////////////////////////////////////////////////////////////
	    // Выработка имитовставки и подписи данных
	    ///////////////////////////////////////////////////////////////////////////

	    // инициализировать алгоритм имитовставки или подписи данных
	    public void SignInit(Mechanism parameters, UInt64 hKey)
	    {
		    // инициализировать алгоритм имитовставки или подписи данных
		    module.SignInit(hSession, parameters, hKey); 
	    }	
	    // обработать данные
	    public void SignUpdate(byte[] data, int dataOff, int dataLen)
	    {
		    // обработать данные
		    module.SignUpdate(hSession, data, dataOff, dataLen); 
	    }
	    // получить имитовставку или подпись данных
	    public int SignFinal(byte[] buff, int bufOff)
	    {
		    // получить имитовставку или подпись данных
		    return module.SignFinal(hSession, buff, bufOff); 
	    }
	    // получить имитовставку или подпись данных
	    public byte[] Sign(byte[] data, int dataOff, int dataLen)
	    {
		    // получить имитовставку или подпись данных
		    return module.Sign(hSession, data, dataOff, dataLen); 
	    }
	    ///////////////////////////////////////////////////////////////////////////
	    // Проверка имитовставки и подписи данных
	    ///////////////////////////////////////////////////////////////////////////

	    // инициализировать алгоритм имитовставки или проверки подписи
	    public void VerifyInit(Mechanism parameters, UInt64 hKey)
	    {
		    // инициализировать алгоритм имитовставки или проверки подписи
		    module.VerifyInit(hSession, parameters, hKey); 
	    }
	    // обработать данные
	    public void VerifyUpdate(byte[] data, int dataOff, int dataLen)
	    {
		    // обработать данные
		    module.VerifyUpdate(hSession, data, dataOff, dataLen); 
	    }
	    // проверить имитовставку или подпись данных
	    public void VerifyFinal(byte[] signature)
	    {
		    // проверить имитовставку или подпись данных
		    module.VerifyFinal(hSession, signature); 
	    }
	    // проверить имитовставку или подпись данных
	    public void Verify(byte[] data, int dataOff, int dataLen, byte[] signature)
	    {
		    // проверить имитовставку или подпись данных
		    module.Verify(hSession, data, dataOff, dataLen, signature); 
	    }
	    ///////////////////////////////////////////////////////////////////////////
	    // Шифрование данных
	    ///////////////////////////////////////////////////////////////////////////
			
	    // инициализировать алгоритм зашифрования
	    public void EncryptInit(Mechanism parameters, UInt64 hKey)
	    {
		    // инициализировать алгоритм зашифрования
		    module.EncryptInit(hSession, parameters, hKey); 
	    }
	    // зашифровать данные
	    public int EncryptUpdate(byte[] data, int dataOff, int dataLen, byte[] buffer, int bufferOff)
	    {
		    // зашифровать данные
		    return module.EncryptUpdate(hSession, data, dataOff, dataLen, buffer, bufferOff); 
	    }
	    // завершить зашифрование данных
	    public int EncryptFinal(byte[] buffer, int bufferOff)
	    {
		    // завершить зашифрование данных
		    return module.EncryptFinal(hSession, buffer, bufferOff); 
	    }
	    // зашифровать данные
	    public byte[] Encrypt(byte[] data, int dataOff, int dataLen)
	    {
		    // зашифровать данные
		    return module.Encrypt(hSession, data, dataOff, dataLen); 
	    }
	    // инициализировать алгоритм расшифрования
	    public void DecryptInit(Mechanism parameters, UInt64 hKey)
	    {
		    // инициализировать алгоритм расшифрования
		    module.DecryptInit(hSession, parameters, hKey); 
	    }
	    // расшифровать данные
	    public int DecryptUpdate(byte[] data, int dataOff, int dataLen, byte[] buffer, int bufferOff)
	    {
		    // расшифровать данные
		    return module.DecryptUpdate(hSession, data, dataOff, dataLen, buffer, bufferOff); 
	    }
	    // завершить расшифрование данных
	    public int DecryptFinal(byte[] buffer, int bufferOff)
	    {
		    // завершить расшифрование данных
		    return module.DecryptFinal(hSession, buffer, bufferOff); 
	    }
	    // расшифровать данные
	    public byte[] Decrypt(byte[] data, int dataOff, int dataLen)
	    {
		    // расшифровать данные
		    return module.Decrypt(hSession, data, dataOff, dataLen); 
	    }
	    ///////////////////////////////////////////////////////////////////////////
	    // Шифрование ключа
	    ///////////////////////////////////////////////////////////////////////////
			
	    // зашифровать ключ
	    public byte[] WrapKey(Mechanism parameters, UInt64 hWrapKey, UInt64 hKey)
	    {
		    // зашифровать ключ
		    return module.WrapKey(hSession, parameters, hWrapKey, hKey); 
	    }
	    // расшифровать ключ
	    public UInt64 UnwrapKey(Mechanism parameters, 
		    UInt64 hWrapKey, byte[] data, Attribute[] attributes)
	    {
		    // расшифровать ключ
		    return module.UnwrapKey(hSession, parameters, hWrapKey, data, attributes); 
	    }
	    ///////////////////////////////////////////////////////////////////////////
	    // Наследование ключа
	    ///////////////////////////////////////////////////////////////////////////
	    public UInt64 DeriveKey(Mechanism parameters, UInt64 hBaseKey, Attribute[] attributes)
	    {
		    // выполнить наследование ключа
		    return module.DeriveKey(hSession, parameters, hBaseKey, attributes); 
	    }
    }; 
}
