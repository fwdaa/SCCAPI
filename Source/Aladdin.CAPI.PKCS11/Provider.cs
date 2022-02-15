using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis; 
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////
	// Криптографический провайдер
	///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public abstract class Provider : CryptoProvider, IRandFactory
	{
		// конструктор
		protected Provider(string name) { this.name = name; } private string name;

        // имя провайдера
        public override string Name { get { return name; }}
		// интерфейс вызова функций
		public abstract Module Module { get; } 

        // возможность импорта ключевой пары в память
        public virtual bool CanImportSessionPair(Applet applet) { return true; }

		///////////////////////////////////////////////////////////////////////////
		// Создание атрибутов
		///////////////////////////////////////////////////////////////////////////
		public Attribute CreateAttribute(ulong type, byte value)
		{
			// создать атрибут
			return new Attribute(type, value); 
		}
		public Attribute CreateAttribute(ulong type, byte[] value)
		{
			// создать атрибут
			return new Attribute(type, value); 
		}
        public Attribute CreateAttribute(ulong type, string value)
		{
			// создать атрибут
			return new Attribute(type, value); 
		}
		public Attribute CreateAttribute(ulong type, ulong value)
        {
	        // создать атрибут
	        return new Attribute(type, Module.EncodeLong(value)); 
        }
		///////////////////////////////////////////////////////////////////////
		// Атрибуты провайдера
		///////////////////////////////////////////////////////////////////////

		// фабрика генераторов случайных данных
		public override IRandFactory CreateRandFactory(SecurityObject scope, bool strong)
        {
	        // проверить область видимости
	        if (scope is Container) return RefObject.AddRef(((Container)scope).Store);
	        
	        // проверить область видимости
	        if (scope is Applet) return RefObject.AddRef((Applet)scope); 
            
            // вернуть фабрику генераторов
            return RefObject.AddRef(this);
        }
        // создать генератор случайных данных
        public override IRand CreateRand(object window)
        { 
	        // получить список считывателей
	        UInt64[] slotList = Module.GetSlotList(true); 
	
	        // для каждого считывателя
	        for (int i = 0; i < slotList.Length; i++)
	        try {
                // получить информацию устройства
                SlotInfo slotInfo = Module.GetSlotInfo(slotList[i]); 
            
                // проверить наличие смарт-карты
                if ((slotInfo.Flags & API.CKF_TOKEN_PRESENT) == 0) continue;

		        // получить информацию устройства
		        TokenInfo tokenInfo = Module.GetTokenInfo(slotList[i]); 

		        // проверить наличие генератора случайных данных
		        if ((tokenInfo.Flags & API.CKF_RNG) == 0) continue; 

                // создать объект смарт-карты
                using (Token token = new Token(this, slotList[i])) 
                {
		            // создать объект апплета
                    using (Applet applet = new Applet(token, slotList[i]))  
                    {
		                // вернуть генератор случайных данных
		                return applet.CreateRand(window);
                    }
                }
	        }
	        // вызвать базовую функцию
	        catch {} return base.CreateRand(window); 
        }
		///////////////////////////////////////////////////////////////////////
		// Управление объектами
		///////////////////////////////////////////////////////////////////////

		// получить хранилище контейнера
		public override string[] EnumerateStores(Scope scope)
        {
            // проверить область видимости
            if (scope != Scope.System) return new string[0]; 

            // выделить память для имен смарт-карт
            List<String> stores = new List<String>(); 
            try { 
	            // получить список считывателей
	            UInt64[] slotList = Module.GetSlotList(true); 

	            // для всех найденных смарт-карт
	            for (int i = 0; i < slotList.Length; i++) 
	            try {
		            // создать объект считывателя
		            using (Slot slot = new Slot(this, slotList[i]))
                    { 
		                // при наличии смарт-карты
		                if (slot.GetState() != PCSC.ReaderState.Card) continue; 
		
		                // добавить смарт-карту в список
		                if (!stores.Contains(slot.Name)) stores.Add(slot.Name); 
                    }
	            }
	            catch {} 
            } 
            // вернуть список смарт-карт
            catch {} return stores.ToArray(); 
        }
		// получить хранилище контейнера
		public override SecurityStore OpenStore(Scope scope, string storeName)
        {
	        // проверить область видимости
	        if (scope != Scope.System) throw new NotFoundException(); 

	        // получить список считывателей
	        UInt64[] slotList = Module.GetSlotList(true); 

	        // для всех найденных смарт-карт
	        for (int i = 0; i < slotList.Length; i++) 
	        {
		        // получить имя считывателя
		        SlotInfo info = Module.GetSlotInfo(slotList[i]); 

		        // проверить совпадение имен
		        if (!info.SlotDescription.Equals(storeName)) continue; 

		        // открыть объект смарт-карты
		        return new Token(this, slotList[i]); 
	        }
	        // при ошибке выбросить исключение
	        throw new NotFoundException(); 
        }
		// найти устройство с реализацией алгоритма
		public Applet FindApplet(SecurityObject scope, ulong algID, ulong usage, int keySize)
        {
	        // проверить область видимости
	        if (scope is Container) 
	        {
                // получить апплет контейнера
                Applet applet = ((Container)scope).Store; 

                // проверить поддержку алгоритма
                if (!applet.Supported(algID, usage, keySize)) return null; 

		        // вернуть устройство для контейнера
		        return RefObject.AddRef(applet);
	        }
	        // проверить область видимости
            if (scope is Applet) { Applet applet = (Applet)scope; 
            
                // проверить поддержку алгоритма
                if (!applet.Supported(algID, usage, keySize)) return null; 

		        // вернуть устройство 
		        return RefObject.AddRef(applet);
            }
	        // получить список считывателей
	        UInt64[] slotList = Module.GetSlotList(true); 
	
	        // для каждого считывателя
	        for (int i = 0; i < slotList.Length; i++)
	        try {
                // получить информацию устройства
                SlotInfo slotInfo = Module.GetSlotInfo(slotList[i]); 
            
                // проверить наличие смарт-карты
                if ((slotInfo.Flags & API.CKF_TOKEN_PRESENT) == 0) continue;
                 
                // создать объект смарт-карты
                using (Token token = new Token(this, slotList[i])) 
                {
                    // открыть объект апплета
                    using (Applet applet = new Applet(token, slotList[i]))
                    {
                        // проверить поддержку алгоритма
                        if (!applet.Supported(algID, usage, keySize)) continue; 
                        
                        // вернуть найденный апплет
                        return RefObject.AddRef(applet);
                    }
                }
            }
            catch {} return null;
        }
		///////////////////////////////////////////////////////////////////////
		// Особенности провайдера
		///////////////////////////////////////////////////////////////////////

		// сгенерировать стартовое значение
		public virtual byte[] GenerateSeed(Applet applet) { return null; } 

		// преобразование типа ключей
		public virtual SecretKey ConvertSecretKey(SessionObject obj, SecretKeyFactory keyFactory)
        {
	        // получить атрибуты ключа
	        Attributes attributes = GetKeyAttributes(obj, 
                CreateAttribute(API.CKA_KEY_TYPE, API.CKK_GENERIC_SECRET) 
            ); 
            // при возможности извлечения значения
            if (attributes[API.CKA_EXTRACTABLE].GetByte() != API.CK_FALSE && 
                attributes[API.CKA_SENSITIVE  ].GetByte() == API.CK_FALSE)
            {
                // получить значение ключа
                Attribute attribute = CreateAttribute(API.CKA_VALUE, obj.GetValue()); 
            
                // добавить атрибут в список
                attributes = attributes.Join(attribute); 
            }
            // при отсутствии на смарт-карте
            if (attributes[API.CKA_TOKEN].Value[0] == 0)
            {
                // проверить наличие значения
                if (attributes[API.CKA_VALUE] == null)
                {
                    // при ошибке выбросить исключение
                    throw new Aladdin.PKCS11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
                }
		        // создать ключ по сеансовому объекту 
		        return new SecretKey(null, keyFactory, attributes); 
	        }
	        else {
                // определить идентификатор слота
                UInt64 slotID = obj.Session.SlotID; 

		        // открыть объект смарт-карты
		        using (Token token = new Token(this, slotID)) 
                {
                    // указать апплет
                    using (Applet applet = new Applet(token, slotID))  
                    {
		                // создать ключ по сеансовому объекту 
		                return new SecretKey(applet, keyFactory, attributes);
                    }
                }
	        }
        }
        // преобразовать тип открытого ключа
		public abstract IPublicKey ConvertPublicKey(Applet applet, SessionObject obj); 

        // преобразовать тип личного ключа
		public abstract PrivateKey ConvertPrivateKey(SecurityObject scope, 
            SessionObject privateObject, IPublicKey publicKey
        ); 
		// преобразование типа ключей
		public SessionObject ToSessionObject(
            Session session, ISecretKey key, Attribute[] keyAttributes)
        {
	        // проверить тип ключа
	        if (key is SecretKey) return ((SecretKey)key).ToSessionObject(session, keyAttributes); 

            // получить значение ключа
            if (key.Value == null) throw new Aladdin.PKCS11.Exception(API.CKR_KEY_UNEXTRACTABLE); 

            // создать список атрибутов
            Attribute[] attributes = new Attribute[] { 

	            // указать тип ключа
	            CreateAttribute(API.CKA_CLASS, API.CKO_SECRET_KEY), 

	            // указать тип ключа
	            CreateAttribute(API.CKA_KEY_TYPE, API.CKK_GENERIC_SECRET), 

	            // указать извлекаемость значения
	            CreateAttribute(API.CKA_EXTRACTABLE, API.CK_TRUE ), 
	            CreateAttribute(API.CKA_SENSITIVE  , API.CK_FALSE), 

                // указать значение ключа
	            CreateAttribute(API.CKA_VALUE, key.Value) 
            }; 
            // создать сеансовый объект
            return session.CreateObject(Attribute.Join(attributes, keyAttributes)); 
        }
		public SessionObject ToSessionObject(Session session, 
            IPublicKey publicKey, MechanismInfo info, Attribute[] keyAttributes)
        {
            // получить атрибуты открытого ключа
            Attribute[] publicKeyAttributes = PublicKeyAttributes(
                null, publicKey, info
            ); 
            // проверить поддержку ключа
            if (publicKeyAttributes == null) throw new NotSupportedException(); 

            // указать тип ключа
	        Attribute[] attributes = new Attribute[] {
		        CreateAttribute(API.CKA_CLASS, API.CKO_PUBLIC_KEY) 
	        }; 
            // добавить атрибуты открытого ключа
	        attributes = Attribute.Join(attributes, publicKeyAttributes); 

            // создать сеансовый объект
            return session.CreateObject(Attribute.Join(attributes, keyAttributes)); 
        }
		public SessionObject ToSessionObject(Session session, 
            IPrivateKey privateKey, MechanismInfo info, Attribute[] keyAttributes)
        {
	        // проверить тип ключа
            if (privateKey is PrivateKey) { PrivateKey pkcs11Key = (PrivateKey)privateKey; 
            
                // создать сеансовый объект
                return pkcs11Key.ToSessionObject(session, keyAttributes);
            }
            // получить атрибуты личного ключа
            Attribute[] privateKeyAttributes = PrivateKeyAttributes(
                null, privateKey, info
            ); 
            // проверить поддержку ключа
            if (privateKeyAttributes == null) throw new NotSupportedException(); 

            // указать тип ключа
            Attribute[] attributes = new Attribute[] {
	            CreateAttribute(API.CKA_CLASS, API.CKO_PRIVATE_KEY)
            };
            // добавить атрибуты личного ключа
            attributes = Attribute.Join(attributes, privateKeyAttributes); 

            // создать сеансовый объект
            return session.CreateObject(Attribute.Join(attributes, keyAttributes)); 
        }
		// атрибуты открытого ключа
		public abstract Attribute[] PublicKeyAttributes(
            Applet applet, IPublicKey publicKey, MechanismInfo info
        ); 
		// атрибуты личного ключа
		public abstract Attribute[] PrivateKeyAttributes(
            Applet applet, IPrivateKey privateKey, MechanismInfo info
        ); 
	    // атрибуты симметричного ключа
	    public virtual Attribute[] SecretKeyAttributes(SecretKeyFactory keyType, int keySize, bool hasValue) 
        { 
            // атрибуты созданного ключа
            if (hasValue) return new Attribute[] {
                  CreateAttribute(API.CKA_KEY_TYPE, API.CKK_GENERIC_SECRET) 
            }; 
            // атрибуты создаваемого ключа
            return new Attribute[] {
                CreateAttribute(API.CKA_KEY_TYPE , API.CKK_GENERIC_SECRET), 
                CreateAttribute(API.CKA_VALUE_LEN, (uint)keySize         ) 
            }; 
        }
		// создать ключ по сеансовому объекту
		public Attributes GetKeyAttributes(SessionObject obj, params Attribute[] attributes)
        {
            if (obj.OnToken())
            {
                // выделить память для атрибутов
                Attribute[] keyAttributes = new Attribute[] { 

	                // задать стандартные типы атрибутов
	                CreateAttribute(API.CKA_TOKEN,       API.CK_TRUE ), 
	                CreateAttribute(API.CKA_EXTRACTABLE, API.CK_TRUE ), 
	                CreateAttribute(API.CKA_SENSITIVE,   API.CK_FALSE), 
            
	                // задать стандартные типы атрибутов
                    new Attribute(API.CKA_CLASS   ), 
	                new Attribute(API.CKA_KEY_TYPE), 
                    new Attribute(API.CKA_ID      )
                }; 
                // указать дополнительные атрибуты
                attributes = Attribute.Join(keyAttributes, attributes); 
            }
            else {
                // выделить память для атрибутов
                Attribute[] keyAttributes = new Attribute[] { 

	                // задать стандартные типы атрибутов
	                CreateAttribute(API.CKA_TOKEN,       API.CK_FALSE), 
	                CreateAttribute(API.CKA_EXTRACTABLE, API.CK_TRUE ), 
	                CreateAttribute(API.CKA_SENSITIVE,   API.CK_FALSE), 
            
	                // задать стандартные типы атрибутов
                    new Attribute(API.CKA_CLASS   ), 
	                new Attribute(API.CKA_KEY_TYPE) 
                }; 
                // указать дополнительные атрибуты
                attributes = Attribute.Join(keyAttributes, attributes); 
            }
            // получить атрибуты объекта
            return new Attributes(obj.GetAttributes(attributes)); 
        }
    }
}
