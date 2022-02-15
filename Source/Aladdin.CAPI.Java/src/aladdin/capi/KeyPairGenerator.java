package aladdin.capi;
import aladdin.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей
///////////////////////////////////////////////////////////////////////////
public abstract class KeyPairGenerator extends RefObject implements IAlgorithm
{
    // фабрика алгоритмов и область видимости
    private final Factory factory; private final SecurityObject scope; private final IRand rand;
    
    // конструктор
    public KeyPairGenerator(Factory factory, SecurityObject scope, IRand rand) 
    { 
        // сохранить область видимости
        this.factory = RefObject.addRef(factory);
        this.scope   = RefObject.addRef(scope  ); 
        this.rand    = RefObject.addRef(rand   ); 
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException
    {
        // освободить выделенные ресурсы
        RefObject.release(rand); RefObject.release(scope); 
        
        // освободить выделенные ресурсы
        RefObject.release(factory); super.onClose();
    }
    // фабрика алгоритмов
    protected final Factory factory() { return factory; }
    // область видимости
    protected final SecurityObject scope() { return scope; }
    // область видимости
    protected final IRand rand() { return rand; }

    // сгенерировать ключи
	public abstract KeyPair generate(byte[] keyID, 
        String keyOID, KeyUsage keyUsage, KeyFlags keyFlags) throws IOException; 
    
}
