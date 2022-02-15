package aladdin.capi;
import aladdin.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Хранилище защищенных объектов
///////////////////////////////////////////////////////////////////////////
public abstract class SecurityStore extends SecurityObject
{
    // криптографический провайдер и область видимости
    private final IProvider provider; private final Scope scope;

    // конструктор
    public SecurityStore(IProvider provider, Scope scope) 
    { 
        // сохранить переданные параметры
        super(null); this.provider = RefObject.addRef(provider); this.scope = scope; 
    } 
    // конструктор
	public SecurityStore(SecurityStore parent) 
    { 
        // сохранить переданные параметры
        super(parent); this.scope = parent.scope; 
        
        // сохранить переданные параметры
        this.provider = RefObject.addRef(parent.provider); 
    } 
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException
    {
        // освободить выделенные ресурсы
        RefObject.release(provider); super.onClose(); 
    }
    // провайдер объекта
    @Override public IProvider provider() { return provider; } 
    // область видимости
    public final Scope scope() { return scope; }

    // информация объекта
    @Override public SecurityInfo info()
    { 
        // информация объекта
        if (store() != null) return super.info(); 

        // информация объекта
        return new SecurityInfo(scope, null, name()); 
    }
    // уникальный идентификатор
    public String getUniqueID() throws IOException { return info().fullName(); }
    
	///////////////////////////////////////////////////////////////////////
    // Поддержка аутентификации
	///////////////////////////////////////////////////////////////////////

    // аутентификация создаваемых дочерних объектов
    public List<Class<? extends Authentication>> getChildAuthenticationTypes(String user) 
    { 
        // аутентификация не поддерживается
        return new ArrayList<Class<? extends Authentication>>(); 
    } 
	///////////////////////////////////////////////////////////////////////
    // Управление объектами
	///////////////////////////////////////////////////////////////////////

    // выполнить разбор имени
    public String[] parseObjectName(String fullName)
    {
        // найти первый разделитель
        int index = fullName.indexOf(File.separatorChar); if (index >= 0)
        {
            // извлечь имя хранилища
            String storeName = fullName.substring(0, index); 

            // извлечь имя объекта
            String name = fullName.substring(index + 1); 

            // вернуть разобранное имя
            return new String[] { storeName, name }; 
        }
        // вернуть разобранное имя
        else return new String[] { fullName }; 
    }
    // перечислить объекты
	public String[] enumerateObjects() { return new String[0]; }  

	// создать объект
	public SecurityObject createObject(IRand rand, 
        Object name, Object authenticationData, Object... parameters)  throws IOException
    {
        // операция не поддерживается
        throw new UnsupportedOperationException(); 
    }
	// открыть объект
	public abstract SecurityObject openObject(
        Object name, String access) throws IOException;

    // удалить объект
	public void deleteObject(Object name, 
        Authentication[] authentications) throws IOException
    {
        // удалить объект из кэша аутентификации
        ExecutionContext.getProviderCache(provider().name()).clearData(info());
    }
	///////////////////////////////////////////////////////////////////////
    // Иерархическое перечисление объектов
	///////////////////////////////////////////////////////////////////////
	public SecurityInfo[] enumerateAllObjects() 
    {
        // создать список описаний объектов
        List<SecurityInfo> infos = new ArrayList<SecurityInfo>(); 

        // для всех объектов
        for (String name : enumerateObjects())
        {
            // открыть объект
            try (SecurityObject obj = openObject(name, "r"))
            {
                // для хранилища
                if (obj instanceof SecurityStore)
                {
                    // перечислить объекты
                    infos.addAll(Arrays.asList(
                        ((SecurityStore)obj).enumerateAllObjects()
                    )); 
                }
                else { 
                    // добавить описание объекта
                    infos.add(new SecurityInfo(scope, fullName(), name)); 
                }
            }
            catch (Throwable e) {}
        }
        // вернуть список объектов
        return infos.toArray(new SecurityInfo[infos.size()]); 
    }
}        
