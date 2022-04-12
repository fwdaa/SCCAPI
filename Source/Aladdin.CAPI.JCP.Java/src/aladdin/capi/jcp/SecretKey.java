package aladdin.capi.jcp;
import aladdin.*; 
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Симметричный ключ
///////////////////////////////////////////////////////////////////////////////
public final class SecretKey extends RefObject implements javax.crypto.SecretKey
{
    private static final long serialVersionUID = -3811029150707481222L;
    
    // используемый провайдер и номер слота
	private final Provider provider; private final int slot;
    // имя алгоритма и используемый ключ
    private final String algorithm; private final ISecretKey secretKey; 
    
    // конструктор
    public SecretKey(Provider provider, String algorithm, ISecretKey secretKey)
    {
        // добавить объект в таблицу
        this.provider = provider; this.slot = provider.addObject(this); 
        
        // сохранить ссылку объекта
        this.algorithm = algorithm; this.secretKey = RefObject.addRef(secretKey); 
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException
    { 
        // уменьшить счетчик ссылок
        RefObject.release(secretKey); 

        // удалить объект из таблицы
        provider.removeObject(slot); super.onClose();
    }
    // алгоритм ключа
    @Override public String getAlgorithm() { return algorithm; }
    // формат ключа 
    @Override public String getFormat() { return "RAW"; }
    // закодированное представление
    @Override public byte[] getEncoded() { return secretKey.value(); }

    // родной личный ключ
    public final ISecretKey get() { return secretKey; }
}
