package aladdin.capi.jcp;
import aladdin.*; 
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Личный ключ
///////////////////////////////////////////////////////////////////////////////
public final class PrivateKey extends RefObject implements java.security.PrivateKey
{
    // номер версии при сериализации
    private static final long serialVersionUID = 7614704878078073265L;

    // используемый провайдер и номер слота
	private final Provider provider; private final int slot;
    // используемый ключ
    private final IPrivateKey privateKey; 
    
    // конструктор
    public PrivateKey(Provider provider, IPrivateKey privateKey)
    {
        // сохранить ссылку объекта
        this.privateKey = RefObject.addRef(privateKey); 
        
        // добавить объект в таблицу
        this.provider = provider; this.slot = provider.addObject(this); 
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException
    { 
        // уменьшить счетчик ссылок
        RefObject.release(privateKey); 
        
        // удалить объект из таблицы
        provider.removeObject(slot); super.onClose();
    }
    // алгоритм ключа
    @Override public String getAlgorithm() { return privateKey.getAlgorithm(); }
    // формат ключа 
    @Override public String getFormat() { return privateKey.getFormat(); }
    // закодированное представление
    @Override public byte[] getEncoded() { return privateKey.getEncoded(); }

    // родной личный ключ
    public final IPrivateKey get() { return privateKey; }
}
