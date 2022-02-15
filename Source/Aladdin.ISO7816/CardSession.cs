namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////
    // Сеанс взаимодействия со смарт-картой
    ///////////////////////////////////////////////////////////////////////////
    public abstract class CardSession : LogicalChannel
    {
        // клиент взаимодействия со смарт-картой и возможности смарт-карты
        private CardClient client; private CardEnvironment environment;
    
        // конструктор
        protected CardSession() : this(null) {}
        
        // конструктор
        protected CardSession(CardClient client) 
        {
            // сохранить переданные параметры
            this.client = client; environment = null;
        } 
        // возможности смарт-карты
        public override CardEnvironment Environment 
        { 
            // возможности смарт-карты
            get { return (environment != null) ? environment : ATR.HistoricalBytes; }
        }
        // сеанс взаимодействия со смарт-картой
        public override CardSession Session { get { return this; }}

        // клиент взаимодействия со смарт-картой
        public CardClient Client { get { return client; }}
        // ATR смарт-карты
        public abstract ATR ATR { get; }

        // инициализировать сеанс
        protected void Init(bool afterReset) { if (!afterReset) return; 
        
            // получить возможности смарт-карты
            if (client != null) { BER.LifeCycle lifeCycle = Environment.LifeCycle; 
        
                // получить код состояния
                ushort sw = (lifeCycle != null) ? lifeCycle.SW : (ushort)0x9000; 
            
                // при запросе от карты
                if ((0x6202 <= sw && sw <= 0x6280) || (0x6402 <= sw && sw <= 0x6480)) 
                {
                    // обработать запрос от карты
                    Response response = client.reply(this, null, sw); 

                    // проверить корректность выполнения
                    ResponseException.Check(response); 
                }
            }
            // получить описание команды описания возможностей
            BER.InitialAccessData initialAccessData = Environment.InitialAccessData; 
        
            // обработать файл EF.ATR
            if (initialAccessData == null) environment = Environment.CombineEFATR(this); 
            else { 
                // выполнить команду
                Response response = Environment.SendCommand(this, initialAccessData.Command); 

                // проверить корректность выполнения
                ResponseException.Check(response); 
            
                // раскодировать объекты
                DataObject[] objects = Environment.DataCoding.Decode(response.Data, true); 

                // скорректировать описание возможностей смарт-карты
                environment = Environment.Combine(objects); 

                // обработать файл EF.ATR
                environment = environment.CombineEFATR(this); 
            }
        } 
	    // заблокировать/разблокировать считыватель
        public abstract void Lock  (); 
        public abstract void Unlock(); 
    
	    // отправить команду смарт-карте
	    public Response SendCommand(byte cla, byte ins, byte p1, byte p2, byte[] data, int ne)
        {
	        // отправить команду смарт-карте
            return Environment.SendCommand(this, cla, ins, p1, p2, data, ne); 
        }
		// отправить команду смарт-карте
		public abstract byte[] SendCommand(params byte[] encoded); 
    }
}
