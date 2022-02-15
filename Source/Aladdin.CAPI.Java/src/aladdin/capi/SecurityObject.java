package aladdin.capi;
import aladdin.*; 
import java.io.*; 
import java.lang.reflect.Array;
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Защищенный объект
///////////////////////////////////////////////////////////////////////////
public abstract class SecurityObject extends RefObject
{
    // хранилище защищенных объектов
    private final SecurityStore store;
    // используемые аутентификации
    private Authentication[] authentications; 

    // конструктор
	public SecurityObject(SecurityStore store) 
    { 
        // сохранить переданные параметры
        this.store = RefObject.addRef(store);  

        // аутентификация отсутствует
        authentications = new Authentication[0]; 
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException
    {
        // освободить выделенные ресурсы
        RefObject.release(store); super.onClose(); 
    }
    ///////////////////////////////////////////////////////////////////////
    // Описание защищенного объекта
    ///////////////////////////////////////////////////////////////////////

    // криптографический провайдер
    public IProvider provider() { return store.provider(); }
    // хранилище объектов
    public SecurityStore store() { return store; }
    
    // информация объекта
    public SecurityInfo info()
    {
        // информация объекта
        return new SecurityInfo(store.scope(), store.fullName(), name()); 
    }
    // имя объекта
    public abstract Object name(); 
    
    // полное имя объекта
    public String fullName() { return info().fullName(); }
    
    ///////////////////////////////////////////////////////////////////////
    // Настройка аутентификации
    ///////////////////////////////////////////////////////////////////////

    // поддерживаемые типы аутентификации
    @SuppressWarnings({"unchecked"}) 
    public Class<? extends Credentials>[] getAuthenticationTypes(String user) 
    { 
        // создать пустой список типов аутентификаций
        Object authenticationTypes = Array.newInstance(Class.class, 0); 
        
        // вернуть пустой список типов аутентификаций
        return (Class<? extends Credentials>[])authenticationTypes; 
    } 
    // получить сервис аутентификации
    public AuthenticationService getAuthenticationService(
        String user, Class<? extends Credentials> authenticationType) 
    { 
        return null; 
    } 
    // проверить необходимость аутентификации
    public boolean isAuthenticationRequired(Throwable e) 
    { 
        // проверить необходимость аутентификации
        if (e instanceof AuthenticationException) return true; 

        // проверить необходимость аутентификации
        return (store != null) ? store.isAuthenticationRequired(e) : false; 
    }
    ///////////////////////////////////////////////////////////////////////
    // Аутентификация
    ///////////////////////////////////////////////////////////////////////

    // получить используемые аутентификации
    public Authentication[] getAuthentications() { return authentications; }

    // установить используемые аутентификации
    public void setAuthentications(Authentication[] value) 
    { 
        // установить аутентификацию
        authentications = (value != null) ? value : new Authentication[0]; 
    }
    // установить аутентификацию
    public void setAuthentication(Authentication value)
    { 
        // установить аутентификацию
        authentications = (value != null) ? new Authentication[] { value } : new Authentication[0]; 
    }
	// выполнить аутентификацию
	public Credentials[] authenticate() throws IOException
	{ 
        // список выполненных аутентификаций
        List<Credentials> credentialsList = new ArrayList<Credentials>(); 

        // выполнить аутентификацию родительского каталога
        if (store != null) credentialsList.addAll(Arrays.asList(store.authenticate())); 
        
        // для всех аутентификаций
        for (int i = 0; i < authentications.length; i++)
        { 
            // выполнить аутентификацию через кэш
            Credentials[] credentials = ExecutionContext.cacheAuthenticate(
                this, authentications[i].user(), authentications[i].types()
            ); 
            // явно выполнить аутентификацию
            if (credentials == null) credentials = authentications[i].authenticate(this); 

            // сохранить результат аутентификации
            credentialsList.addAll(Arrays.asList(credentials)); 

            // сохранить пройденную аутентификацию
            if (credentials.length == 1) authentications[i] = credentials[0];
            else { 
                // определить число оставшихся аутентификаций
                int remaining = authentications.length - (i + 1); 

                // изменить общее число аутентификаций
                authentications = Arrays.copyOf(
                    authentications, authentications.length + credentials.length - 1
                ); 
                // скопировать непройденные аутентификации
                System.arraycopy(authentications, i + 1, 
                    authentications, i + credentials.length, remaining
                ); 
                // для всех пройденных аутентификаций
                for (int j = 0; j < credentials.length; j++)
                { 
                    // скопировать пройденную аутентификацию
                    authentications[i + j] = credentials[j]; 
                }
            }
        }
        // вернуть пройденные аутентификации
        return credentialsList.toArray(new Credentials[credentialsList.size()]);  
	}
}
