package aladdin.capi.jcp;
import aladdin.RefObject;
import aladdin.capi.*; 
import java.io.*; 
import java.util.*;

///////////////////////////////////////////////////////////////////////////////
// Криптографический провайдер
///////////////////////////////////////////////////////////////////////////////
public abstract class Provider extends java.security.Provider implements Closeable
{
    // номер версии для сериализации
    private static final long serialVersionUID = -733657477642391790L;
    
    // таблица объектов и фабрика генераторов случайных данных
    private final List<Closeable> objects; private final IRand rand;
    
    // конструктор
	public Provider(String name, double version, String info) 
	{ 
		// указать имя криптопровайдера
		super(name, version, info); rand = new Rand(null); 
        
        // создать таблицу объектов
        objects = new ArrayList<Closeable>(); 
    } 
    // освободить выделенные ресурсы
    @Override public void close() throws IOException { rand.close(); 
    
        // для всех объектов
        for (Closeable object : objects) 
        {
            // проверить наличие объекта
            if (object == null) continue; 
            
            // освободить ресурсы алгоритма
            try { object.close(); } catch (IOException e) {}
        }
    }
    // генератор случайных данных
    public final IRand getRand() { return rand; }
    
    // получить объект
    public final Closeable getObject(int slot) 
    { 
        // получить объект
        return objects.get(slot); 
    }
    // установить объект
    public final void setObject(int slot, Closeable object) 
    { 
        // переустановить объект
        clearObject(slot); objects.set(slot, object); 
    }
    // освободить ресурсы объекта
    public final void clearObject(int slot)
    {
        // получить используемый алгоритм
        Closeable object = objects.get(slot); if (object == null) return; 

        // освободить ресурсы объекта
        try { object.close(); } catch (IOException e) {} objects.set(slot, null);
    }
    // зарегистрировать личный ключ
    public final PrivateKey registerPrivateKey(IPrivateKey privateKey)
    {
        // добавить ключ в таблицу
        objects.add(RefObject.addRef(privateKey)); 
        
        // вернуть зарегистрированный ключ
        return new PrivateKey(this, objects.size() - 1, privateKey); 
    }
    // зарегистрировать симметричный ключ
    public final SecretKey registerSecretKey(ISecretKey secretKey)
    {
        // добавить ключ в таблицу
        objects.add(RefObject.addRef(secretKey)); 
        
        // вернуть зарегистрированный ключ
        return new SecretKey(this, objects.size() - 1, secretKey); 
    }
	// получить фабрику алгоритмов
	public abstract Factory getFactory(); 
    
    // провайдер контейнеров PKCS12
    public final aladdin.capi.pkcs12.CryptoProvider pkcs12() 
    {
        // получить фабрику алгоритмов
        Factory factory = getFactory(); 
        
        // вернуть провайдер контейнеров PKCS12 /* TODO */
        return new aladdin.capi.pkcs12.CryptoProvider(
            null, Arrays.asList(new Factory[] { factory })
        ); 
    }
}; 
