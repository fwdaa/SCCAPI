package aladdin.capi;
import aladdin.*; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkcs.pkcs8.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Личный ключ
///////////////////////////////////////////////////////////////////////////
public abstract class PrivateKey extends RefObject implements IPrivateKey
{
    // номер версии для сериализации
    private static final long serialVersionUID = -6721876224961760277L;

    private final Factory        factory; // фабрика алгоритмов
    private final SecurityObject scope;   // область видимости
    private final String         keyOID;  // идентификатор ключа
    
	// конструктор
	public PrivateKey(Factory factory, SecurityObject scope, String keyOID)
	{
        // сохранить фабрику алгоритмов
        this.factory = RefObject.addRef(factory); 
        
        // сохранить область видимости
        this.scope = RefObject.addRef(scope); this.keyOID = keyOID; 
	}
    // освободить выделенные ресурсы
    @Override
    protected void onClose() throws IOException
    {
        // освободить выделенные ресурсы
        RefObject.release(scope); RefObject.release(factory); super.onClose();
    }
	@Override public final Factory       factory() { return factory; }	
	@Override public final SecurityStore scope() 
    { 
        // при указании хранилища контейнеров
        if (scope instanceof SecurityStore)
        {
            // извлечь хранилище контейнеров
            return (SecurityStore)scope; 
        }
        // извлечь хранилище контейнеров
        return (scope != null) ? scope.store() : null; 
    }	
    @Override public final Container container()
    {
        // контейнер ключа
        return (scope instanceof Container) ? (Container)scope : null; 
    }
    // идентификатор ключа
    @Override public final String keyOID() { return keyOID; }
    
    // фабрика кодирования
    @Override public final KeyFactory keyFactory()
    {
        // фабрика кодирования
        return factory().getKeyFactory(keyOID); 
    }
    // закодировать ключ
    @Override public final PrivateKeyInfo encode(Attributes attributes) throws IOException
    {
        // закодировать ключ
        return keyFactory().encodePrivateKey(this, attributes); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Реализация java.security.PrivateKey
    ////////////////////////////////////////////////////////////////////////////
    
    // идентификатор ключа
    @Override public final String getAlgorithm() { return keyOID; }
    
    // формат закодированного представления
    @Override public final String getFormat() { return "PKCS#8"; }
    
    // закодированное представление
    @Override public final byte[] getEncoded() 
    { 
        // получить фабрику кодирования
        KeyFactory keyFactory = keyFactory(); 
        
        // проверить наличие фабрики
        if (keyFactory == null) return null; 
        try { 
            // получить закодированное представление
            return keyFactory.encodePrivateKey(this, null).encoded(); 
        }
        // обработать возможную ошибку
        catch (Throwable e) { return null; }
    } 
}
