package aladdin.pcsc;
import aladdin.remoting.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Группа считывателей
///////////////////////////////////////////////////////////////////////////
public final class ReaderGroup
{
    // модуль, область видимости и группы считывателей
	private final Module module; private final ReaderScope scope; private final String[] groups;	

    // конструктор
    ReaderGroup(Module module, ReaderScope scope, String[] groups)
    {
        // проверить указание групп
        if (groups == null) groups = new String[] { "SCard$AllReaders" }; 

        // сохранить переданные параметры
        this.module = module; this.scope = scope; this.groups = groups; 
    }
    // запустить прослушиватель событий считывателя
    public RemoteClientControl startListener(IReaderHandler readerHandler, 
        IBackgroundHandler handler) throws java.lang.Exception
    {
	    // указать функцию удаленного потока
	    try (ReaderListener client = new ReaderListener(module, scope, groups, readerHandler)) 
        {
            // запустить поток
            return client.start(handler); 
        }
    }
    // перечислить считыватели
    public Reader[] enumerateReaders() throws IOException
    {
        // создать системный контекст
        long hSysContext = module.establishContext(ReaderScope.SYSTEM); 
        try {
            // перечислить системные считыватели
            if (scope.equals(ReaderScope.SYSTEM)) return enumerateReaders(hSysContext, hSysContext);

            // создать пользовательский контекст
            long hUserContext = module.establishContext(ReaderScope.USER); 
            try {
                // перечислить считыватели
                return enumerateReaders(hUserContext, hSysContext); 
            }
            // освободить контекст
            finally { module.releaseContext(hUserContext); } 
        }
        // освободить контекст
        finally { module.releaseContext(hSysContext); }
    }
    // перечислить считыватели
    private Reader[] enumerateReaders(long hContext, long hSysContext) throws IOException
    {
	    // создать список считывателей
	    List<Reader> readers = new ArrayList<Reader>();

	    // перечислить системные считыватели
	    List<String> sysNames = Arrays.asList(module.listReaders(hSysContext, groups));

        // при перечислении системных считывателей
        if (scope.equals(ReaderScope.SYSTEM)) for (int i = 0; i < sysNames.size(); i++)
	    {
	        // создать описание считывателя
	        readers.add(new Reader(module, scope, sysNames.get(i))); 
	    }
        else { 
	        // перечислить пользовательские считыватели
	        String[] userNames = module.listReaders(hContext, groups);

            // для каждого считывателя
	        for (int i = 0; i < userNames.length; i++)
	        {
	            // проверить принадлежность системной области
	            ReaderScope readerScope = sysNames.contains(userNames[i]) ? ReaderScope.SYSTEM : ReaderScope.USER; 

	            // проверить область видимости
	            if (scope.equals(ReaderScope.RESERVED) || readerScope.equals(ReaderScope.USER))
	            { 
	                // создать объект считывателя
	                readers.add(new Reader(module, readerScope, userNames[i])); 
	            }
            }
	    }
        // вернуть список считывателей
        return readers.toArray(new Reader[readers.size()]);
    }
    ///////////////////////////////////////////////////////////////////////
    // Обработчик событий считывателей
    ///////////////////////////////////////////////////////////////////////
    static class Handler implements aladdin.pcsc.Module.IReaderHandler
    {
        // группа считывателей и список известных считывателей
        private final ReaderGroup readerGroup; private final List<Reader> knownReaders;
        // обработчик событий считывателей и системный контекст
        private final IReaderHandler readerHandler; private final long hSysContext; 
        
        // конструктор
        public Handler(ReaderGroup readerGroup, IReaderHandler readerHandler, long hSysContext)
        {
            // сохранить переданные параметры
            this.readerHandler = readerHandler; this.hSysContext = hSysContext; 
            
            // создать список известных считывателей
            this.readerGroup = readerGroup; knownReaders = new ArrayList<Reader>(); 
        }
        // перечислить считыватели
        @Override public String[] listReaders(long hContext) throws IOException
        {
            // заново перечислить считыватели
            Reader[] readers = readerGroup.enumerateReaders(hContext, hSysContext); 

            // создать список имен считывателей
            String[] names = new String[readers.length]; 

            // для всех считывателей
            for (int i = 0; i < readers.length; i++) 
            {
                // найти объект считывателя
                Reader reader = findReader(readers[i].name()); 
                
                // добавить информацию считывателя
                if (reader == null) knownReaders.add(readers[i]); 
                
                // указать имя считывателя
                names[i] = readers[i].name(); 
            }
            return names; 
        }
        // создать объект считывателя
        protected Reader findReader(String readerName)
        {
            // для всех считывателей из списка
            for (Reader reader : knownReaders)
            {
                // проверить совпадение имени
                if (reader.name().equals(readerName)) return reader; 
            }
            return null; 
        }
        // добавление считывателя
        @Override public void onInsertReader(long hContext, String readerName) throws java.lang.Exception
        {
            // создать объект считывателя
            Reader reader = findReader(readerName);
            
            // вызвать функцию обработки
            if (reader != null) readerHandler.onInsertReader(reader);
        }
        // удаление считывателя
        @Override public void onRemoveReader(long hContext, String readerName) throws java.lang.Exception
        {
            // создать объект считывателя
            Reader reader = findReader(readerName); 
            
            // вызвать функцию обработки
            if (reader != null) readerHandler.onRemoveReader(reader);
        }
        // добавление смарт-карты
        @Override public void onInsertCard(long hContext, String readerName) throws java.lang.Exception
        {
            // создать объект считывателя
            Reader reader = findReader(readerName); 
            
            // вызвать функцию обработки
            if (reader != null) readerHandler.onInsertCard(reader);
        }
        // удаление смарт-карты
        @Override public void onRemoveCard(long hContext, String readerName) throws java.lang.Exception
        {
            // создать объект считывателя
            Reader reader = findReader(readerName); 
            
            // вызвать функцию обработки
            if (reader != null) readerHandler.onRemoveCard(reader);
        }
    }
}
