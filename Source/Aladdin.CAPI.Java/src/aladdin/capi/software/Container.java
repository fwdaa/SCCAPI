package aladdin.capi.software;
import aladdin.RefObject;
import aladdin.capi.*;
import aladdin.capi.auth.*;
import java.io.*; 
import java.lang.reflect.*;
        
///////////////////////////////////////////////////////////////////////////
// Программный контейнер
///////////////////////////////////////////////////////////////////////////
public abstract class Container extends aladdin.capi.Container
{
    // поток вывода
    private final ContainerStream stream; 

    // открыть существующий контейнер
	protected Container(ContainerStore store, ContainerStream stream)
    {        
        // сохранить переданные параметры
        super(store, stream.name()); this.stream = RefObject.addRef(stream); 
    } 
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException
    {
        // освободить выделенные ресурсы
        RefObject.release(stream); super.onClose();
    }
    // уникальный идентификатор
    @Override public String getUniqueID() { return stream.uniqueID(); }
    
    ///////////////////////////////////////////////////////////////////////
    // Поддержка аутентификации
    ///////////////////////////////////////////////////////////////////////
    @Override
    @SuppressWarnings({"unchecked"}) 
    public Class<? extends Credentials>[] getAuthenticationTypes(String user) 
    { 
        // создать список типов аутентификаций
        Object authenticationTypes = Array.newInstance(Class.class, 1); 
        
        // указать поддерживаемую аутентификацию
        Array.set(authenticationTypes, 0, PasswordCredentials.class); 
        
        // вернуть список типов аутентификаций
        return (Class<? extends Credentials>[])authenticationTypes;
    } 
	public void setPassword(String value) throws IOException
    {
        // установить тип аутентификации
        Authentication authentication = new PasswordCredentials("USER", value); 

        // выполнить аутентификацию
        setAuthentication(authentication); authenticate(); 
    }
    ///////////////////////////////////////////////////////////////////////
	// содержимое контейнера
	public abstract byte[] encoded(); 

	// сохранить пару ключей для алгоритма
    @Override
	public byte[] setKeyPair(IRand rand, KeyPair keyPair, 
        KeyUsage keyUsage, KeyFlags keyFlags) throws IOException
    { 
        // сохранить данные контейнера
        flush(); return keyPair.keyID; 
    }
	// удалить пару ключей для алгоритма
    @Override
	public void deleteKeyPair(byte[] keyID) throws IOException { flush(); }

    // сохранить данные контейнера
    public void flush() throws IOException { stream.write(encoded()); }
}
