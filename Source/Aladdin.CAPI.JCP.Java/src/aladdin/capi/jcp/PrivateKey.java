package aladdin.capi.jcp;
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Личный ключ
///////////////////////////////////////////////////////////////////////////////
public class PrivateKey implements java.security.PrivateKey, Closeable
{
    // номер версии при сериализации
    private static final long serialVersionUID = -5111126973676236264L;

    // используемый провайдер и номер слота
	private final Provider provider; private final int slot;
    // используемый ключ
    private final IPrivateKey privateKey; 
    
    // конструктор
    public PrivateKey(Provider provider, int slot, IPrivateKey privateKey)
    {
        // сохранить переданные параметры
        this.provider = provider; this.slot = slot; this.privateKey = privateKey; 
    }
    // освободить выделенные ресурсы
    @Override public void close() { provider.clearObject(slot); }
    
    // алгоритм ключа
    @Override public String getAlgorithm() { return privateKey.getAlgorithm(); }
    // формат ключа 
    @Override public String getFormat() { return privateKey.getFormat(); }
    // закодированное представление
    @Override public byte[] getEncoded() { return privateKey.getEncoded(); }

    // родной личный ключ
    public final IPrivateKey get() { return privateKey; }
}
