package aladdin.pcsc;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Считыватель смарт-карт
///////////////////////////////////////////////////////////////////////////
public final class Reader implements IReader
{
    // модуль, область видимости и логическое имя 
    private final Module module; private final ReaderScope scope; private final String name;

    // конструктор
    Reader(Module module, ReaderScope scope, String name) 
    {
	    // сохранить переданные параметры
	    this.module = module; this.scope = scope; this.name = name; 
    }
    // логическое имя считывателя
    @Override public String name() { return name; } 

    // состояние считывателя
    @Override public ReaderState getState() throws IOException
    {
        // создать используемый контекст
        long hContext = module.establishContext(scope); 
        try {
            // получить информацию о состоянии
            return module.getReaderState(hContext, name()); 
        }
        // освободить выделенные ресурсы
        finally { module.releaseContext(hContext); }
    }
    // открыть сеанс работы со смарт-картой
    public ReaderSession createSession(OpenMode openMode, int protocols) throws IOException
    {
        // открыть сеанс работы со смарт-картой
        return createSession(openMode, protocols, false); 
    }
    // открыть сеанс работы со смарт-картой после перезагрузки
    public ReaderSession createSession(OpenMode openMode, int protocols, boolean reset) throws IOException
    {
        // перезагрузить карту
        if (reset) resetCard();
        
        // создать объект сеанса
        return new ReaderSession(module, scope, name(), openMode, protocols, reset); 
    }
    // смарт-карта считывателя
    @Override public ICard openCard() throws IOException
    {
        // вернуть смарт-карту
        return new Card(module, scope, this); 
    }
	// извлечь смарт-карту
	public void ejectCard() throws IOException
    {
        // указать используемый протокол
        int[] protocol = new int[] { Protocol.RAW };
            
        // создать используемый контекст
        long hContext = module.establishContext(scope); 
        try {
            // открыть считыватель
            long hSession = module.connect(
                hContext, name, OpenMode.DIRECT, protocol
            );
	        // извлечь смарт-карту
            module.disconnect(hSession, CloseMode.EJECT); 
        }
        // освободить выделенные ресурсы
        finally { module.releaseContext(hContext); } 
    }
    // перезагрузить смарт-карту
    public void resetCard() throws IOException
    {
        // указать используемый протокол
        int[] protocol = new int[] { Protocol.RAW };
            
	    // создать используемый контекст
	    long hContext = module.establishContext(scope); 
        try {
            // открыть считыватель
            long hSession = module.connect(
                hContext, name, OpenMode.DIRECT, protocol
            );
	        // перезагрузить смарт-карту
            module.disconnect(hSession, CloseMode.RESET); 
        }
        // освободить выделенные ресурсы
        finally { module.releaseContext(hContext); } 
    }
    // выключить смарт-карту
    public void shutdownCard() throws IOException
    {
        // указать используемый протокол
        int[] protocol = new int[] { Protocol.RAW };
        
	    // создать используемый контекст
	    long hContext = module.establishContext(scope); 
        try {
            // открыть считыватель
            long hSession = module.connect(
                hContext, name, OpenMode.DIRECT, protocol
            );
            // выключить смарт-карту
            module.disconnect(hSession, CloseMode.UNPOWER); 
        }
        // освободить выделенные ресурсы
        finally { module.releaseContext(hContext); } 
    }
}
