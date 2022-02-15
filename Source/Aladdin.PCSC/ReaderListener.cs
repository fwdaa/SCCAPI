using System; 
using System.ComponentModel;

namespace Aladdin.PCSC
{
    ///////////////////////////////////////////////////////////////////////////
    // Функция обработки удаленного потока
    ///////////////////////////////////////////////////////////////////////////
    public sealed class ReaderListener : Remoting.RemoteClient
    {
        // модуль и область видимости
	    private Module module; private ReaderScope scope; 
        // набор групп и обработчик
        private string[] groups; private IReaderHandler readerHandler; 

	    // конструктор
	    internal ReaderListener(Module module, ReaderScope scope, string[] groups, IReaderHandler readerHandler) 
	    {
		    // сохранить переданные параметры
		    this.module = module; this.scope = scope; 
            
		    // сохранить переданные параметры
            this.groups = groups; this.readerHandler = readerHandler; 
        }
	    // создать объект управления
	    protected override Remoting.RemoteClientControl CreateRemoteControl(Remoting.IBackgroundTask task)
	    {
            // указать область видимости
            ReaderScope readerScope = (scope == ReaderScope.System) ? ReaderScope.System : ReaderScope.User; 

		     // создать объект управления
		     return new ListenerControl(task, module, readerScope); 
	    }
	    // функция потока
	    public override void ThreadProc(Remoting.IBackgroundTask task, DoWorkEventArgs args)
	    {
            // извлечь объект управления 
            ListenerControl control = (ListenerControl)args.Argument; 
            
            // извлечь контекст
            ulong hContext = control.ContextHandle; uint code = API.SCARD_S_SUCCESS; 

            // указать группу считывателей
            ReaderGroup readerGroup = new ReaderGroup(module, scope, groups); 

		    // для системной области видимости
		    if (scope == ReaderScope.System)
		    {
                // указать используемый обработчик
                ReaderGroup.Handler handler = new ReaderGroup.Handler(
                    readerGroup, readerHandler, hContext
                ); 
                // прослушать события считывателей
                code = module.ListenReaders(hContext, handler); 
		    }
		    else {
			    // создать системный контекст
		        ulong hSysContext = module.EstablishContext(ReaderScope.System); 
                try {
                    // указать используемый обработчик
                    ReaderGroup.Handler handler = new ReaderGroup.Handler(
                        readerGroup, readerHandler, hSysContext
                    ); 
                    // прослушать события считывателей
                    code = module.ListenReaders(hContext, handler); 
                }
                // закрыть используемый контекст
                finally { module.ReleaseContext(hSysContext); } 
		    }
            // указать признак отмены
            args.Cancel = (code == API.SCARD_E_CANCELLED); 
	    }
        ///////////////////////////////////////////////////////////////////////
        // Объект управления удаленным потоком
        ///////////////////////////////////////////////////////////////////////
        private class ListenerControl : Remoting.RemoteClientControl
        {
            // модуль и описатель контекста
	        private Module module; private ulong hContext;

	        // конструктор
	        public ListenerControl(Remoting.IBackgroundTask task, Module module, ReaderScope scope) : base(task) 
            { 
		        // создать используемый контекст
		        this.hContext = module.EstablishContext(scope); this.module = module; 
            } 
            // деструктор
            protected override void OnDispose() { module.ReleaseContext(hContext); base.OnDispose(); }

            // описатель контекста
            public ulong ContextHandle { get { return hContext; }}

	        // завершить удаленный поток
	        public override void Cancel() 
            { 
	            // завершить удаленный поток
                base.Cancel(); module.CancelContext(hContext);  
            }
        }
    }
}
