using System;
using System.Collections.Generic;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////
	// Криптографический контейнер 
	///////////////////////////////////////////////////////////////////////////
	public class Container : CAPI.Container
	{
		// режим открытия контейнера
		private ulong mode;

		// конструктор
		public Container(Applet applet, string name, ulong mode)

			// сохранить переданные параметры
			: base(applet, name) { this.mode = mode; } 

		// криптографический провайдер
		public new Provider Provider { get { return Store.Provider; }}

		// смарт-карта контейнера
		public new Applet Store { get { return (Applet)base.Store; }} 

		// определить идентификаторы ключей
		public override byte[][] GetKeyIDs()
        {
	        // открыть сеанс
	        using (Session session = Store.OpenSession(API.CKS_RO_PUBLIC_SESSION))
            { 
	            // получить идентификаторы объектов
	            return Store.GetKeyIDs(session, Name.ToString()); 
            }
        }
		// получить открытый ключ
		public override IPublicKey GetPublicKey(byte[] keyID)
        {
	        // выделить память для атрибутов поиска
	        Attribute[] attributes = new Attribute[] { 

		        // указать для поиска тип объекта
		        Store.Provider.CreateAttribute(API.CKA_CLASS, API.CKO_PUBLIC_KEY), 

		        // указать идентификатор ключа
		        Store.Provider.CreateAttribute(API.CKA_ID, keyID)
	        }; 
	        // открыть сеанс
	        using (Session session = Store.OpenSession(API.CKS_RO_PUBLIC_SESSION)) 
            {
	            // найти открытый ключ
	            SessionObject obj = session.FindTokenObject(Name.ToString(), attributes);

				// преобразовать открытый ключ
				if (obj != null) { IPublicKey publicKey = Provider.ConvertPublicKey(Store, obj); 
            
					// проверить поддержку ключа
					if (publicKey == null) throw new NotSupportedException(); return publicKey; 
				}
			}
			// получить сертификат
			Certificate certificate = GetCertificate(keyID);

			// проверить наличие сертификата
			if (certificate == null) throw new NotFoundException();

			// вернуть открытый ключ сертификата
			return certificate.GetPublicKey(Store.Provider); 
		}
		// получить личный ключ
		public override IPrivateKey GetPrivateKey(byte[] keyID)
        {
			// получить открытый ключ
			IPublicKey publicKey = GetPublicKey(keyID); 

	        // выделить память для атрибутов поиска
	        Attribute[] privateAttributes = new Attribute[] { 

		        // указать для поиска тип объекта
		        Store.Provider.CreateAttribute(API.CKA_CLASS, API.CKO_PRIVATE_KEY), 

		        // указать идентификатор ключа
		        Store.Provider.CreateAttribute(API.CKA_ID, keyID)
	        }; 
	        // открыть сеанс
	        using (Session session = Store.OpenSession(API.CKS_RO_USER_FUNCTIONS)) 
            {
	            // найти личный ключ
	            SessionObject privateObject = session.FindTokenObject(
                    Name.ToString(), privateAttributes
                ); 
	            // проверить наличие ключа
	            if (privateObject == null) throw new NotFoundException();  

                // преобразовать личный ключ
                IPrivateKey privateKey = Provider.ConvertPrivateKey(
                    this, privateObject, publicKey
                ); 
                // проверить поддержку ключа
                if (privateKey == null) throw new NotSupportedException(); return privateKey; 
            }
        }
		// получить сертификат открытого ключа
		public override Certificate GetCertificate(byte[] keyID)
        {
	        // выделить память для атрибутов поиска
	        Attribute[] attributes = new Attribute[] { 

		        // указать для поиска тип объекта
		        Store.Provider.CreateAttribute(API.CKA_CLASS, API.CKO_CERTIFICATE), 

		        // указать идентификатор ключа
		        Store.Provider.CreateAttribute(API.CKA_ID, keyID)
	        }; 
	        // открыть сеанс
	        using (Session session = Store.OpenSession(API.CKS_RO_PUBLIC_SESSION)) 
	        try { 
		        // найти сертификат
		        SessionObject obj = session.FindTokenObject(Name.ToString(), attributes); 

		        // проверить наличие сертификата
		        if (obj == null) return null;

		        // создать объект сертификата
		        return new Certificate(obj.GetValue()); 
	        }
	        // сертификат отсутствует
	        catch { return null; }
        }
		// сохранить сертификат открытого ключа
		public override void SetCertificate(byte[] keyID, Certificate certificate)
        {
            // указать требуемое состояние сеанса
            ulong state = (mode == 0) ? API.CKS_RO_USER_FUNCTIONS : API.CKS_RW_USER_FUNCTIONS; 

	        // выделить память для атрибутов поиска
	        Attribute[] attributes = new Attribute[] { 

		        // указать тип объекта
		        Store.Provider.CreateAttribute(API.CKA_CLASS, API.CKO_CERTIFICATE),

		        // указать тип сертификата
		        Store.Provider.CreateAttribute(API.CKA_CERTIFICATE_TYPE, API.CKC_X_509),

		        // указать субъект сертификата
		        Store.Provider.CreateAttribute(API.CKA_SUBJECT, certificate.Subject.Encoded),

		        // указать значение сертификата
		        Store.Provider.CreateAttribute(API.CKA_VALUE, certificate.Encoded),

		        // определить идентификатор сертификата
		        Store.Provider.CreateAttribute(API.CKA_ID, keyID)
	        }; 
	        // открыть сеанс
	        using (Session session = Store.OpenSession(state))
            { 
	            // создать сертификат на смарт-карте
	            try { session.CreateTokenObject(Name.ToString(), attributes); }

                // при возникновении ошибки
                catch (Aladdin.PKCS11.Exception e) 
                {
                    // проверить код ошибки
                    if (e.ErrorCode != API.CKR_ATTRIBUTE_TYPE_INVALID) throw; 

	                // выделить память для атрибутов поиска
	                attributes = new Attribute[] { 

		                // указать тип объекта
		                Store.Provider.CreateAttribute(API.CKA_CLASS, API.CKO_CERTIFICATE),

		                // указать значение сертификата
		                Store.Provider.CreateAttribute(API.CKA_VALUE, certificate.Encoded),

		                // определить идентификатор сертификата
		                Store.Provider.CreateAttribute(API.CKA_ID, keyID)
	                }; 
	                // создать сертификат на смарт-карте
	                session.CreateTokenObject(Name.ToString(), attributes); 
                }
            }
        }
        // импортировать пару ключей
		public override KeyPair ImportKeyPair(IRand rand, IPublicKey publicKey, 
            IPrivateKey privateKey, KeyUsage keyUsage, KeyFlags keyFlags)
		{
            // открыть сеанс
            using (Session session = Store.OpenSession(API.CKS_RW_USER_FUNCTIONS)) 
            {
                // подготовится к записи ключевой пары
                byte[] keyID = Store.PrepareKeyPair(session, Name.ToString(), null, rand, keyUsage); 

                // сохранить пару ключей
                SessionObject[] objs = SetKeyPair(
                    session, keyID, rand, publicKey, privateKey, keyUsage, keyFlags
                );
                // преобразовать открытый ключ
                publicKey = Provider.ConvertPublicKey(Store, objs[0]); 
            
                // проверить поддержку ключа
                if (publicKey == null) throw new NotSupportedException(); 
            
                // преобразовать личный ключ
                using (privateKey = Provider.ConvertPrivateKey(this, objs[1], publicKey))
                { 
                    // проверить поддержку ключа
                    if (privateKey == null) throw new NotSupportedException(); 

                    // вернуть импортированную пару ключей
                    return new KeyPair(publicKey, privateKey, keyID); 
                }
            }
		}
		// сохранить пару ключей
		public override byte[] SetKeyPair(IRand rand, 
			KeyPair keyPair, KeyUsage keyUsage, KeyFlags keyFlags)
		{
            // извлечь ключи
            IPublicKey publicKey = keyPair.PublicKey; IPrivateKey privateKey = keyPair.PrivateKey;

            // открыть сеанс
            using (Session session = Store.OpenSession(API.CKS_RW_USER_FUNCTIONS)) 
            {
                // подготовится к записи ключевой пары
                byte[] keyID = Store.PrepareKeyPair(session, Name.ToString(), keyPair.KeyID, rand, keyUsage); 

                // сохранить пару ключей
                SetKeyPair(session, keyID, rand, publicKey, privateKey, keyUsage, keyFlags); return keyID;  
            }
		}
		// сохранить пару ключей
		private SessionObject[] SetKeyPair(Session session, byte[] keyID, IRand rand, 
            IPublicKey publicKey, IPrivateKey privateKey, KeyUsage keyUsage, KeyFlags keyFlags)
        {
            // получить атрибуты ключей
            Attribute[] publicAttributes = Store.Provider.PublicKeyAttributes(Store, publicKey, null); 

            // проверить поддержку ключей
            if (publicAttributes == null) throw new NotSupportedException();
        
            // получить атрибуты ключей
            Attribute[] privateAttributes = Store.Provider.PrivateKeyAttributes(Store, privateKey, null); 

            // проверить поддержку ключей
            if (privateAttributes == null) throw new NotSupportedException();
        
            // создать списки атрибутов
            List<Attribute> pubAttributes  = new List<Attribute>(publicAttributes ); 
            List<Attribute> privAttributes = new List<Attribute>(privateAttributes); 

            // указать классы объектов
	        pubAttributes .Add(Store.Provider.CreateAttribute(API.CKA_CLASS, API.CKO_PUBLIC_KEY ));
            privAttributes.Add(Store.Provider.CreateAttribute(API.CKA_CLASS, API.CKO_PRIVATE_KEY));
            
            // указать принадлежность токену
            pubAttributes .Add(Store.Provider.CreateAttribute(API.CKA_TOKEN  , API.CK_TRUE));
            privAttributes.Add(Store.Provider.CreateAttribute(API.CKA_TOKEN  , API.CK_TRUE));
            privAttributes.Add(Store.Provider.CreateAttribute(API.CKA_PRIVATE, API.CK_TRUE));

            // указать имя контейнера
            pubAttributes .Add(Store.Provider.CreateAttribute(API.CKA_LABEL, Name.ToString()));
            privAttributes.Add(Store.Provider.CreateAttribute(API.CKA_LABEL, Name.ToString()));

	        // проверить возможность экспорта
	        byte exportable = ((keyFlags & KeyFlags.Exportable) != KeyFlags.None) ? API.CK_TRUE : API.CK_FALSE; 
            
	        // указать признак извлекаемости ключа
	        privAttributes.Add(Store.Provider.CreateAttribute(API.CKA_EXTRACTABLE, exportable));

            // указать идентификатор ключей
            pubAttributes .Add(new Attribute(API.CKA_ID, keyID)); 
            privAttributes.Add(new Attribute(API.CKA_ID, keyID)); 
            
            // сохранить пару ключей 
            return session.CreateKeyPair(keyUsage, pubAttributes.ToArray(), privAttributes.ToArray());
        }
		// удалить пару ключей
		public override void DeleteKeyPair(byte[] keyID)
        {
	        // выделить память для атрибутов поиска
	        Attribute[] attributes = new Attribute[] {
                Store.Provider.CreateAttribute(API.CKA_ID, keyID)
            }; 
            // указать требуемое состояние сеанса
            ulong state = (mode == 0) ? API.CKS_RO_USER_FUNCTIONS : API.CKS_RW_USER_FUNCTIONS; 

	        // открыть сеанс
	        using (Session session = Store.OpenSession(state)) 
            {
	            // перечислить объекты контейнера
	            SessionObject[] objects = session.FindTokenObjects(Name.ToString(), attributes); 

	            // удалить объекты контейнера
	            foreach (SessionObject obj in objects) session.DestroyObject(obj); 
            }
        }
		// удалить все ключи
		public override void DeleteKeys()
        {
            // указать требуемое состояние сеанса
            ulong state = (mode == 0) ? API.CKS_RO_USER_FUNCTIONS : API.CKS_RW_USER_FUNCTIONS; 

	        // открыть сеанс
	        using (Session session = Store.OpenSession(state)) 
            {
	            // перечислить объекты контейнера
	            SessionObject[] objects = session.FindTokenObjects(Name.ToString(), null); 

	            // удалить все объекты контейнера
	            foreach (SessionObject obj in objects) session.DestroyObject(obj); 
            }
        }
	}
}
