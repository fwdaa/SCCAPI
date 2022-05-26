package aladdin.capi.software;
import aladdin.capi.*;
import aladdin.capi.auth.*;
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Хранилище программных контейнеров
///////////////////////////////////////////////////////////////////////////
public abstract class ContainerStore extends aladdin.capi.ContainerStore
{
	// конструктор
	public ContainerStore(CryptoProvider provider, Scope scope) { super(provider, scope); }
	// конструктор
	public ContainerStore(SecurityStore parent) { super(parent); }
    
    // используемый провайдер
    @Override
    public CryptoProvider provider() { return (CryptoProvider)super.provider(); }

    ///////////////////////////////////////////////////////////////////////
	// Поддержка аутентификации
	///////////////////////////////////////////////////////////////////////
    @Override
    public List<Class<? extends Authentication>> getChildAuthenticationTypes(String user) 
    { 
        // создать список поддерживаемых аутентификаций
        List<Class<? extends Authentication>> authenticationTypes = 
            new ArrayList<Class<? extends Authentication>>(); 
        
        // указать поддерживаемую аутентификацию
        authenticationTypes.add(PasswordCredentials.class); return authenticationTypes;
    } 
	///////////////////////////////////////////////////////////////////////
	// Управление контейнерами
	///////////////////////////////////////////////////////////////////////
	// создать контейнер
    @Override
	public SecurityObject createObject(IRand rand, 
        Object name, Object authenticationData, Object... parameters) throws IOException
    {
		// проверить наличие пароля 
		if (authenticationData == null) throw new IllegalArgumentException();
        
        // выполнить преобразование типа
        String password = (String)authenticationData; 
        try { 
            // создать контейнер
            try (ContainerStream stream = createStream(name)) 
            {
                // создать контейнер
                Container container = provider().createContainer(
                    rand, this, stream, password, parameters[0]
                );
                // записать содержимое контейнера
                stream.write(container.encoded()); return container;  
            }
        }
        // обработать возможную ошибку
        catch (Throwable e) { deleteStream(name); throw e; }
    }
	// открыть контейнер
    @Override
	public SecurityObject openObject(
        Object name, String access) throws IOException
	{
        // открыть контейнер
        try (ContainerStream stream = openStream(name, access)) 
        {
            // вернуть контейнер
            return provider().openContainer(this, stream);
        }
	}
	// удалить контейнер
    @Override
    public void deleteObject(Object name, 
        Authentication[] authentications) throws IOException
    { 
	    // удалить контейнер
        deleteStream(name); super.deleteObject(name, authentications);
    }
	///////////////////////////////////////////////////////////////////////
	// Управление физическими потоками
	///////////////////////////////////////////////////////////////////////

    // создать поток
    protected ContainerStream createStream(Object name) throws IOException
    {
        // операция не поддерживается
        throw new UnsupportedOperationException(); 
    }
    // открыть поток
    protected ContainerStream openStream(Object name, String access) throws IOException
    {
        // операция не поддерживается
        throw new UnsupportedOperationException(); 
    }
    // удалить поток
    protected void deleteStream(Object name) throws IOException
    {
        // операция не поддерживается
        throw new UnsupportedOperationException(); 
    }
}
