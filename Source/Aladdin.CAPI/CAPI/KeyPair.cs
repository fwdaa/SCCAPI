using System; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////////
    // Пара ключей ассиметричного алгоритма
    ///////////////////////////////////////////////////////////////////////////////
    public class KeyPair : RefObject
    {
	    // записать ключи в контейнер
        public KeyPair(SecurityObject scope, IRand rand, IPublicKey publicKey, 
            IPrivateKey privateKey, byte[] keyID, KeyUsage keyUsage, KeyFlags keyFlags) 
	    {
            // проверить указание контейнера
            if (!(scope is Container)) 
            {
                // сохранить переданные параметры
                PublicKey = publicKey; PrivateKey = RefObject.AddRef(privateKey); KeyID = keyID; 
            }
            // выполнить преобразование типа
            else { Container container = (Container)scope; 

                // указать пару ключей
                using (KeyPair keyPair = new KeyPair(publicKey, privateKey, keyID))
                { 
                    // записать ключи в контейнер
		            if (rand != null) KeyID = container.SetKeyPair(rand, keyPair, keyUsage, keyFlags);

                    // указать генератор случайных данных
                    else using (rand = container.Provider.CreateRand(container, null))
                    {
                        // записать ключи в контейнер
		                KeyID = container.SetKeyPair(rand, keyPair, keyUsage, keyFlags);
                    }
                }
                // получить открытый ключ
                PublicKey = container.GetPublicKey(KeyID); 

                // получить личный ключ
                PrivateKey = container.GetPrivateKey(KeyID); 
            }
	    }
        // конструктор
        public KeyPair(IPublicKey publicKey, IPrivateKey privateKey, byte[] keyID)
        {        
            // сохранить переданные параметры
            PublicKey = publicKey; PrivateKey = RefObject.AddRef(privateKey); KeyID = keyID; 
        }
        // освободить используемые ресурсы
        protected override void OnDispose()
        {
            // освободить используемые ресурсы
            RefObject.Release(PrivateKey); base.OnDispose();
        }
        // пара ключей ассиметричного алгоритма
        public readonly IPublicKey  PublicKey;  // открытый ключ
        public readonly IPrivateKey PrivateKey; // личный ключ
        public readonly byte[]      KeyID;      // идентификатор пары ключей

	    // закодировать ключи
	    public ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo Encode(ASN1.ISO.Attributes attributes)
	    {
            // получить фабрику кодирования
            KeyFactory keyFactory = PrivateKey.KeyFactory; 
        
            // проверить наличие фабрики
            if (keyFactory == null) throw new NotSupportedException(); 
        
            // закодировать пару ключей
            return keyFactory.EncodeKeyPair(PrivateKey, PublicKey, attributes); 
	    }
    }
}
