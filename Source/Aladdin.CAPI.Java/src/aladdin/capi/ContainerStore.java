package aladdin.capi;
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Хранилище контейнеров
///////////////////////////////////////////////////////////////////////////
public abstract class ContainerStore extends SecurityStore
{
    // конструктор
    public ContainerStore(IProvider provider, Scope scope) { super(provider, scope); }
    // конструктор
	public ContainerStore(SecurityStore parent) { super(parent); }

    // используемый провайдер
    @Override public CryptoProvider provider() { return (CryptoProvider)super.provider(); }
    
	///////////////////////////////////////////////////////////////////////
    // Иерархическое перечисление объектов
	///////////////////////////////////////////////////////////////////////
    @Override public String[] parseObjectName(String fullName)
    {
        // вернуть разобранное имя
        return new String[] { fullName }; 
    }
	@Override public SecurityInfo[] enumerateAllObjects()
    {
        // создать список описаний объектов
        List<SecurityInfo> infos = new ArrayList<SecurityInfo>(); 

        // для всех объектов
        for (String name : enumerateObjects())
        {
            // добавить описание объекта
            infos.add(new SecurityInfo(scope(), fullName(), name)); 
        }
        // вернуть список описаний объектов
        return infos.toArray(new SecurityInfo[infos.size()]); 
    }
}
