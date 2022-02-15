package aladdin.capi;
import aladdin.*; 
import aladdin.asn1.iso.*;
import aladdin.asn1.iso.pkcs.pkcs8.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Пара ключей ассиметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
public class KeyPair extends RefObject
{
    // конструктор
    public KeyPair(IPublicKey publicKey, IPrivateKey privateKey, byte[] keyID)
    {        
        // сохранить переданные параметры
        this.publicKey = publicKey; this.keyID = keyID;
        
        // сохранить переданные параметры
        this.privateKey = RefObject.addRef(privateKey); 
    } 
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException
    {
        // освободить выделенные ресурсы
        RefObject.release(privateKey); super.onClose();
    }
    // пара ключей ассиметричного алгоритма
    public final IPublicKey     publicKey;  // открытый ключ
    public final IPrivateKey    privateKey; // личный ключ
    public final byte[]         keyID;      // идентификатор пары
    
	// закодировать ключи
	public final PrivateKeyInfo encode(Attributes attributes) throws IOException
	{
        // получить фабрику кодирования
        KeyFactory keyFactory = privateKey.keyFactory(); 
        
        // проверить наличие фабрики
        if (keyFactory == null) throw new UnsupportedOperationException(); 
        
        // закодировать пару ключей
        return keyFactory.encodeKeyPair(privateKey, publicKey, attributes); 
	}
    // записать ключи в контейнер
    public final KeyPair copyTo(IRand rand, SecurityObject scope, 
        KeyUsage keyUsage, KeyFlags keyFlags) throws IOException
    {
        // создать копию ключевой пары 
        if (scope == null) return new KeyPair(publicKey, privateKey, keyID); 
        
        // проверить корректность параметров
         if (!(scope instanceof Container)) throw new IllegalArgumentException(); 
        
        // выполнить преобразование типа
        Container container = (Container)scope; byte[] id = null; 
        
        // записать ключи в контейнер
        if (rand != null) id = container.setKeyPair(rand, this, keyUsage, keyFlags);

        // получить генератор случайных чисел
        else try (IRand containerRand = container.provider().createRand(container, null))
        {
            // записать ключи в контейнер
            id = container.setKeyPair(containerRand, this, keyUsage, keyFlags);
        }
        // вернуть пару ключей контейнера
        return new KeyPair(container.getPublicKey(id), container.getPrivateKey(id), id); 
    }
}
