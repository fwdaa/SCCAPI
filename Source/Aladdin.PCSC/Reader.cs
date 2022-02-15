namespace Aladdin.PCSC
{
    ///////////////////////////////////////////////////////////////////////////
	// Считыватель смарт-карт
	///////////////////////////////////////////////////////////////////////////
	public sealed class Reader : IReader
	{
	    // модуль, область видимости и логическое имя 
	    private Module module; private ReaderScope scope; private string name;

	    // конструктор
	    public Reader(Module module, ReaderScope scope, string name) 
	    {
		    // сохранить переданные параметры
		    this.module = module; this.scope = scope; this.name = name; 
        }
        // область видимости 
        public ReaderScope Scope { get { return scope; }}

	    // логическое имя считывателя
	    public string Name { get { return name; }} 

	    // состояние считывателя
	    public ReaderState GetState()
        {
	        // создать используемый контекст
	        ulong hContext = module.EstablishContext(scope); 
            try {
                // получить информацию о состоянии
                return module.GetReaderState(hContext, Name); 
            }
            // освободить выделенные ресурсы
            finally { module.ReleaseContext(hContext); }
        }
        // открыть сеанс работы со смарт-картой
		public ReaderSession CreateSession(OpenMode openMode, Protocol protocols)
        {
            // открыть сеанс работы со смарт-картой
            return CreateSession(openMode, protocols, false); 
        }
        // открыть сеанс работы со смарт-картой после перезагрузки
		public ReaderSession CreateSession(OpenMode openMode, Protocol protocols, bool reset)
        {
            // выполнить перезагрузку
	        if (reset) ResetCard(); 
            
            // вернуть объект сеанса
            return new ReaderSession(module, scope, Name, openMode, protocols, reset); 
        }
	    // смарт-карта считывателя
	    public ICard OpenCard()
        {
            // указать режим открытия сеанса
            OpenMode openMode = OpenMode.Shared; Protocol protocols = Protocol.T0 | Protocol.T1; 

            // создать сеанс со считывателем
            using (ReaderSession session = CreateSession(openMode, protocols))
            {
	            // вернуть смарт-карту
	            return new Card(module, scope, this); 
            }
        }
		// извлечь смарт-карту
		public void EjectCard()
        {
            // указать режим открытия сеанса
            OpenMode openMode = OpenMode.Direct; Protocol protocol = Protocol.Raw;
            
	        // создать используемый контекст
	        ulong hContext = module.EstablishContext(scope); 
            try {
	            // открыть считыватель
	            ulong hSession = module.Connect(hContext, Name, openMode, ref protocol);
                
		        // извлечь смарт-карту
                module.Disconnect(hSession, CloseMode.Eject); 
            }
            // освободить выделенные ресурсы
            finally { module.ReleaseContext(hContext); } 
        }
		// перезагрузить смарт-карту
        public void ResetCard()
        {
            // указать режим открытия сеанса
            OpenMode openMode = OpenMode.Direct; Protocol protocol = Protocol.Raw;
            
	        // создать используемый контекст
	        ulong hContext = module.EstablishContext(scope); 
            try {
	            // открыть считыватель
	            ulong hSession = module.Connect(hContext, Name, openMode, ref protocol);
                
		        // перезагрузить смарт-карту
                module.Disconnect(hSession, CloseMode.Reset); 
            }
            // освободить выделенные ресурсы
            finally { module.ReleaseContext(hContext); } 
        }
        // выключить смарт-карту
        public void ShutdownCard()
        {
            // указать режим открытия сеанса
            OpenMode openMode = OpenMode.Direct; Protocol protocol = Protocol.Raw;
            
	        // создать используемый контекст
	        ulong hContext = module.EstablishContext(scope); 
            try {
	            // открыть считыватель
	            ulong hSession = module.Connect(hContext, Name, openMode, ref protocol);
                
                // выключить смарт-карту
                module.Disconnect(hSession, CloseMode.Unpower); 
            }
            // освободить выделенные ресурсы
            finally { module.ReleaseContext(hContext); } 
        }
	}
}
