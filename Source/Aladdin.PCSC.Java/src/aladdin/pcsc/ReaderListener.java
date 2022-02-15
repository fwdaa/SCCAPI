package aladdin.pcsc;
import aladdin.async.*;
import aladdin.remoting.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Функция обработки удаленного потока
///////////////////////////////////////////////////////////////////////////
public final class ReaderListener extends RemoteClient 
{
    // модуль и область видимости
    private final Module module; private final ReaderScope scope; 
    // набор групп и обработчик
    private final String[] groups; private final IReaderHandler readerHandler; 

    // конструктор
    ReaderListener(Module module, ReaderScope scope, String[] groups, IReaderHandler readerHandler)
    {
	    // сохранить переданные параметры
	    this.module = module; this.scope = scope; 
        
	    // сохранить переданные параметры
        this.groups = groups; this.readerHandler = readerHandler; 
    }
	// создать объект управления
	@Override protected RemoteClientControl createRemoteControl(IBackgroundTask task) throws IOException
	{
        // указать область видимости
        ReaderScope readerScope = (scope == ReaderScope.SYSTEM) ? ReaderScope.SYSTEM : ReaderScope.USER; 

	    // создать объект управления
	    return new ListenerControl(task, module, readerScope); 
	}
	// функция потока
	@Override public void run(IBackgroundTask task, DoWorkEventArgs args) throws IOException
	{
        // извлечь контекст
        ListenerControl control = (ListenerControl)args.argument; 
            
        // извлечь контекст
        long hContext = control.hContext; int code = API.SCARD_S_SUCCESS; 
        
        // указать группу считывателей
        ReaderGroup readerGroup = new ReaderGroup(module, scope, groups); 
        
	    // для системной области видимости
	    if (scope.equals(ReaderScope.SYSTEM))
	    {
            // указать используемый обработчик
            ReaderGroup.Handler handler = new ReaderGroup.Handler(
                readerGroup, readerHandler, hContext
            ); 
            // прослушать события считывателей
            code = module.listenReaders(hContext, handler); 
	    }
	    else {
		    // создать системный контекст
	        long hSysContext = module.establishContext(ReaderScope.SYSTEM); 
            try {
                // указать используемый обработчик
                ReaderGroup.Handler handler = new ReaderGroup.Handler(
                    readerGroup, readerHandler, hSysContext
                ); 
                // прослушать события считывателей
                code = module.listenReaders(hContext, handler); 
            }
            // закрыть используемый контекст
            finally { module.releaseContext(hSysContext); }
	    }
        // указать признак отмены
        args.cancel = (code == API.SCARD_E_CANCELLED); 
	}
    ///////////////////////////////////////////////////////////////////////
    // Объект управления удаленным потоком
    ///////////////////////////////////////////////////////////////////////
    private static class ListenerControl extends RemoteClientControl
    {
        // модуль и описатель контекста
        private final Module module; private final long hContext;

	    // конструктор
	    public ListenerControl(IBackgroundTask task, Module module, ReaderScope scope) throws IOException
        { 
            // создать используемый контекст
            super(task); this.module = module; hContext = module.establishContext(scope);
        } 
        // деструктор
        @Override protected void onClose() throws IOException
        { 
            // освободить используемый контекст
            module.releaseContext(hContext); super.onClose();  
        }
	    // завершить удаленный поток
	    @Override public void cancel() throws IOException
        { 
	        // завершить удаленный поток
            super.cancel(); module.cancelContext(hContext); 
        }
    }
}
