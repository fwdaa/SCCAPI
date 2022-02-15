namespace Aladdin.PCSC
{
	///////////////////////////////////////////////////////////////////////
	// Сеанс работы со считывателем
	///////////////////////////////////////////////////////////////////////
	public sealed class ReaderSession : ISO7816.CardSession
	{
		// модуль, описатель контекста и сеанса
		private Module module; private ulong hContext; private ulong hSession; 
		// используемый протокол, ATR смарт-карты и необходимость закрытия
		private Protocol protocol; ISO7816.ATR atr; private bool dispose;

		// конструктор 
		public ReaderSession(Module module, ReaderScope scope, 
            string readerName, OpenMode openMode, Protocol protocols, bool afterReset)
		{
			// сохранить переданные параметры
			this.module = module; protocol = protocols; dispose = true; 

	        // создать используемый контекст
	        hContext = module.EstablishContext(scope); 
            try { 
	            // открыть считыватель
	            hSession = module.Connect(hContext, readerName, openMode, ref protocol);

                // получить ATR смарт-карты
                atr = new ISO7816.ATR(module.GetReaderAttribute(hSession, API.SCARD_ATTR_ATR_STRING)); 

                // инициализировать сеанс
                Init(afterReset); 
            }
            // освободить выделенные ресурсы
            catch { module.ReleaseContext(hContext); throw; }
        }
		// конструктор 
		public ReaderSession(Module module, ulong hContext, ulong hSession, Protocol protocol)
		{
			// сохранить переданные параметры
			this.module = module; this.hContext = hContext; this.hSession = hSession; 

            // сохранить переданные параметры
            this.protocol = protocol; this.dispose = false; 

            // получить ATR смарт-карты
            atr = new ISO7816.ATR(module.GetReaderAttribute(hSession, API.SCARD_ATTR_ATR_STRING)); 
        }
		// деструктор
		protected override void OnDispose() 
        { 
            // закрыть сеанс
            if (dispose) { module.Disconnect(hSession, CloseMode.Leave); 
            
                // закрыть контекст
                module.ReleaseContext(hContext); 
            }
            base.OnDispose(); 
		}
        // ATR смарт-карты
        public override ISO7816.ATR ATR { get { return atr; }}

        // используемый протокол
        public Protocol Protocol { get { return protocol; }}

		// получить логические имена считывателя
		public string[] GetReaderNames()
        {
            // вернуть логические имена считывателя
            return module.GetReaderStatus(hSession).readers; 
        }
        // получить атрибут считывателя/смарт-карты
        public byte[] GetAttribute(uint attrId)
        {
            // получить атрибут считывателя/смарт-карты
            return module.GetReaderAttribute(hSession, attrId); 
        }
		// заблокировать смарт-карту
        public override void Lock() 
        { 
		    // заблокировать смарт-карту
            module.BeginTransaction(hSession); 
        } 
        // разблокировать смарт-карту
        public override void Unlock() 
        { 
		    // разблокировать смарт-карту
            module.EndTransaction(hSession, CloseMode.Leave); 
        }  
		// отправить команду считывателю
		public byte[] SendControl(uint code, params byte[] data)
        {
		    // отправить команду считывателю
            return module.SendControl(hSession, code, data, 32768); 
        }
		// отправить команду смарт-карте
		public override byte[] SendCommand(params byte[] encoded)
        {
		    // отправить команду смарт-карте
            return module.SendCommand(hSession, protocol, encoded, 32768); 
        }
    }
}
