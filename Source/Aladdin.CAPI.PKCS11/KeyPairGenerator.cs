using System;
using System.Collections.Generic;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм генерации ключей
	///////////////////////////////////////////////////////////////////////////
	public abstract class KeyPairGenerator : CAPI.KeyPairGenerator
	{
		// конструктор
		protected KeyPairGenerator(Applet applet, SecurityObject scope, IRand rand) 
			
			// сохранить переданные параметры
			: base(applet.Provider, scope, rand) { this.applet = RefObject.AddRef(applet); } 

        // деструктор
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(applet); base.OnDispose();
        }
		// используемое устройство
		public Applet Applet { get { return applet; }} private Applet applet;

		// параметры алгоритма
		protected abstract Mechanism GetParameters(Session sesssion, string keyOID); 

		// сгенерировать пару ключей
		public override KeyPair Generate(byte[] keyID, string keyOID, KeyUsage keyUsage, KeyFlags keyFlags)
        {
	        // сгенерировать пару ключей при отсутствии контейнера
	        if (!(Scope is Container)) return Generate(keyOID, keyUsage); 

	        // определить имя контейнера
	        Container container = (Container)Scope; string name = container.Name.ToString();

	        // создать списки атрибутов
	        List<Attribute> pubAttributes  = new List<Attribute>(GetPublicAttributes(keyOID)); 
	        List<Attribute> privAttributes = new List<Attribute>(GetPrivateAttributes(keyOID)); 

	        // указать принадлежность токену
	        pubAttributes .Add(applet.Provider.CreateAttribute(API.CKA_TOKEN  , API.CK_TRUE));
	        privAttributes.Add(applet.Provider.CreateAttribute(API.CKA_TOKEN  , API.CK_TRUE));
	        privAttributes.Add(applet.Provider.CreateAttribute(API.CKA_PRIVATE, API.CK_TRUE));
	
	        // указать имя контейнера
	        pubAttributes .Add(applet.Provider.CreateAttribute(API.CKA_LABEL, name));
	        privAttributes.Add(applet.Provider.CreateAttribute(API.CKA_LABEL, name));

	        // проверить возможность экспортирта
	        byte exportable = ((keyFlags & KeyFlags.Exportable) != KeyFlags.None) ? API.CK_TRUE : API.CK_FALSE; 
            
	        // указать признак извлекаемости ключа
	        privAttributes.Add(applet.Provider.CreateAttribute(API.CKA_EXTRACTABLE, exportable));

	        // открыть сеанс
	        using (Session session = applet.OpenSession(API.CKS_RW_USER_FUNCTIONS)) 
	        {
                // подготовится к генерации ключевой пары
                keyID = applet.PrepareKeyPair(session, name, keyID, Rand, keyUsage); 

	            // указать идентификатор ключей
	            pubAttributes .Add(applet.Provider.CreateAttribute(API.CKA_ID, keyID)); 
	            privAttributes.Add(applet.Provider.CreateAttribute(API.CKA_ID, keyID)); 

	            // получить параметры алгоритма
	            Mechanism parameters = GetParameters(session, keyOID); 

                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(parameters.AlgID); 
                
                // сгенерировать пару ключей
                SessionObject[] sessionKeys = session.GenerateKeyPair(
                    parameters, keyUsage, pubAttributes.ToArray(), privAttributes.ToArray()
                ); 
                try {  
	                // преобразовать объект открытого ключа
	                IPublicKey publicKey = applet.Provider.ConvertPublicKey(
                        applet, sessionKeys[0]
                    ); 
                    // проверить поддержку ключа
                    if (publicKey == null) throw new NotSupportedException(); 

	                // преобразовать объект личного ключа
	                using (IPrivateKey privateKey = applet.Provider.ConvertPrivateKey(
		                container, sessionKeys[1], publicKey)) 
                    {
                        // проверить поддержку ключа
                        if (privateKey == null) throw new NotSupportedException(); 

	                    // вернуть созданную пару ключей
	                    return new KeyPair(publicKey, privateKey, keyID);  
                    }
                }
                catch { 
	                // удалить открытый и личный ключ
	                session.DestroyObject(sessionKeys[0]); 
	                session.DestroyObject(sessionKeys[1]); throw; 
                }
            }
        }
		// сгенерировать пару ключей
		public virtual KeyPair Generate(string keyOID, KeyUsage keyUsage)
        {
	        // открыть сеанс
	        using (Session session = applet.OpenSession(API.CKS_RO_PUBLIC_SESSION)) 
	        {
	            // сгенерировать пару ключей
	            SessionObject[] sessionKeys = Generate(session, keyOID, keyUsage); 
                try {  
	                // преобразовать объект открытого ключа
	                IPublicKey publicKey = applet.Provider.ConvertPublicKey(
                        applet, sessionKeys[0]
                    ); 
                    // проверить поддержку ключа
                    if (publicKey == null) throw new NotSupportedException(); 

	                // преобразовать объект личного ключа
	                using (IPrivateKey privateKey = applet.Provider.ConvertPrivateKey(
                        Scope, sessionKeys[1], publicKey))
                    {
                        // проверить поддержку ключа
                        if (privateKey == null) throw new NotSupportedException(); 

	                    // вернуть созданную пару ключей
	                    return new KeyPair(publicKey, privateKey, null); 
                    }
                }
                // удалить открытый и личный ключ
                finally { session.DestroyObject(sessionKeys[0]); session.DestroyObject(sessionKeys[1]); }
            }
        }
		// сгенерировать пару ключей
		public SessionObject[] Generate(Session session, string keyOID, KeyUsage keyUsage)
        {
            // создать списки атрибутов
            List<Attribute> pubAttributes  = new List<Attribute>(GetPublicAttributes(keyOID)); 
            List<Attribute> privAttributes = new List<Attribute>(GetPrivateAttributes(keyOID)); 

            // указать принадлежность токену
            pubAttributes .Add(applet.Provider.CreateAttribute(API.CKA_TOKEN      , API.CK_FALSE));
            privAttributes.Add(applet.Provider.CreateAttribute(API.CKA_TOKEN      , API.CK_FALSE));
            privAttributes.Add(applet.Provider.CreateAttribute(API.CKA_PRIVATE    , API.CK_FALSE));
	        privAttributes.Add(applet.Provider.CreateAttribute(API.CKA_EXTRACTABLE, API.CK_TRUE ));

            // получить параметры алгоритма
            Mechanism parameters = GetParameters(session, keyOID); 
                
            // сгенерировать пару ключей
            return session.GenerateKeyPair(parameters, 
                keyUsage, pubAttributes.ToArray(), privAttributes.ToArray() 
            );
        }
		// атрибуты открытого и личного ключа
		protected abstract Attribute[] GetPublicAttributes (string keyOID);
		protected virtual  Attribute[] GetPrivateAttributes(string keyOID) { return new Attribute[0]; }
	}
}
