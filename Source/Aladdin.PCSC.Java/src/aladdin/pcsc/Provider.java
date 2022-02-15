package aladdin.pcsc;
import aladdin.async.*;
import aladdin.remoting.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////
// Смарт-карточная подсистема
///////////////////////////////////////////////////////////////////////
public class Provider
{
    // конструктор
    public Provider(Module module) { this.module = module; } 

    // используемый модуль
    protected Module module() { return module; } private final Module module;

    // создать обобщенную группу считывателей
	public ReaderGroup getReaderGroup(String[] groups)
    {
	    // создать обобщенную группу считывателей
        return new ReaderGroup(module, ReaderScope.RESERVED, groups); 
    }
    // создать обобщенную группу считывателей
	public ReaderGroup getReaderGroup(ReaderScope scope, String[] groups)
    {
	    // создать обобщенную группу считывателей
        return new ReaderGroup(module, scope, groups); 
    }
	// перечислить группы считывателей
	public String[] enumerateReaderGroups() throws IOException
    {
        // создать используемый контекст
        long hContext = module.establishContext(ReaderScope.USER); 
        try {
            // перечислить группы считывателей
            return module.listReaderGroups(hContext); 
        }
        // освободить контекст
        finally { module.releaseContext(hContext); }
    }
	// перечислить группы считывателей
	public String[] enumerateReaderGroups(ReaderScope scope) throws IOException
    {
	    // создать список системных групп
	    List<String> systemGroups = new ArrayList<String>(); 

        // создать используемый контекст
        long hSysContext = module.establishContext(ReaderScope.SYSTEM); 
        try {
	        // перечислить группы считывателей
	        String[] groups = module.listReaderGroups(hSysContext); 

	        // вернуть системные группы считывателей
	        if (scope.equals(ReaderScope.SYSTEM)) return groups; 

            // добавить системные группы в список
            systemGroups = Arrays.asList(groups); 
        }
        // освободить контекст
        finally { module.releaseContext(hSysContext); }

	    // создать пустой список групп
	    List<String> userGroups = new ArrayList<String>(); 

        // создать используемый контекст
        long hUserContext = module.establishContext(ReaderScope.USER); 
        try {
	        // перечислить группы считывателей
	        for (String group : module.listReaderGroups(hUserContext))
            {
	            // проверить отсутствие системной группы
	            if (!systemGroups.contains(group)) userGroups.add(group); 
            }
            // вернуть список групп
            return userGroups.toArray(new String[userGroups.size()]); 
        }
        // освободить контекст
        finally { module.releaseContext(hUserContext); } 
    }
    // перечислить считыватели
    public Reader[] enumerateReaders() throws IOException
    {
        // получить обобщенную группу считывателей
        ReaderGroup readerGroup = getReaderGroup(null); 
            
        // перечислить считыватели
        return readerGroup.enumerateReaders(); 
    }
    // перечислить считыватели
    public Reader[] enumerateReaders(ReaderScope scope) throws IOException
    {
        // получить обобщенную группу считывателей
        ReaderGroup readerGroup = getReaderGroup(scope, null); 
            
        // перечислить считыватели
        return readerGroup.enumerateReaders(); 
    }
	// получить описание считывателя
	public Reader getReader(ReaderScope scope, String name) 
    { 
		// проверить корректность параметров
		if (scope.equals(ReaderScope.RESERVED)) throw new IllegalArgumentException(); 

		// получить описание считывателя
        return new Reader(module, scope, name); 
    }
    // запустить прослушиватель событий считывателей
    public RemoteClientControl startListener(IReaderHandler readerHandler, 
        IBackgroundHandler handler) throws java.lang.Exception
    {
        // указать обобщенную группу считывателей
        ReaderGroup readerGroup = getReaderGroup(null); 

        // запустить прослушиватель событий считывателей
        return readerGroup.startListener(readerHandler, handler); 
    }
    // запустить прослушиватель событий считывателей
    public RemoteClientControl startListener(
        ReaderScope scope, IReaderHandler readerHandler, 
        IBackgroundHandler handler) throws java.lang.Exception
    {
        // указать обобщенную группу считывателей
        ReaderGroup readerGroup = getReaderGroup(scope, null); 

        // запустить прослушиватель событий считывателей
        return readerGroup.startListener(readerHandler, handler); 
    }
}
