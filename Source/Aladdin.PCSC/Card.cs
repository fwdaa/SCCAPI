using System; 

namespace Aladdin.PCSC
{
	///////////////////////////////////////////////////////////////////////////
	// Криптографическая смарт-карта
	///////////////////////////////////////////////////////////////////////////
	public sealed class Card : ICard
	{
        // модуль и область видимости
        private Module module; private ReaderScope scope; 
        // считыватель смарт-карты и ATR
        private Reader reader; private byte[] atr; 

        // производитель и модель смарт-карты
        private string manufacturer; private string model; 
        // номер версии и серийный номер
        private Version version; private byte[] serial; 

        // конструктор
        public Card(Module module, ReaderScope scope, Reader reader)
        {
            // сохранить переданные параметры
            this.module = module; this.scope = scope; this.reader = reader;

            // указать режим открытия сеанса
            OpenMode openMode = OpenMode.Shared; Protocol protocols = Protocol.T0 | Protocol.T1; 

            // создать сеанс со считывателем
            using (ReaderSession session = reader.CreateSession(openMode, protocols))
            {
                // получить ATR смарт-карты
                atr = session.ATR.Encoded; manufacturer = null; model = null; version = null; serial = null; 
                try { 
                    ISO7816.CardEnvironment historicalBytes = session.ATR.HistoricalBytes; 

                    ISO7816.BER.CountryIndicator        prop1 = historicalBytes.CountryIndicator;
                    ISO7816.BER.IssuerIndicator         prop2 = historicalBytes.IssuerIndicator; 
                    ISO7816.BER.CardServiceData         prop3 = historicalBytes.CardServiceData; 
                    ISO7816.BER.InitialAccessData       prop4 = historicalBytes.InitialAccessData;
                    ISO7816.BER.CardIssuerData          prop5 = historicalBytes.CardIssuerData; 
                    ISO7816.BER.PreIssuingData          prop6 = historicalBytes.PreIssuingData; 
                    ISO7816.BER.CardCapabilities        prop7 = historicalBytes.CardCapabilities;
                    ISO7816.BER.LifeCycle               prop8 = historicalBytes.LifeCycle; 
                    ISO7816.BER.ApplicationIdentifier   propF = historicalBytes.ApplicationIdentifier;

                    ISO7816.Response response1 = session.SendCommand(
                        0x00, 0xA4, 0x04, 0x00, new byte[0], 256
                    ); 
                    ISO7816.Response response2 = session.SendCommand(
                        0x00, 0xA4, 0x00, 0x00, new byte[] { 0x3F, 0x00 }, 256
                    ); 
                    ISO7816.Response response3 = session.SendCommand(
                        0x00, 0xA4, 0x01, 0x00, new byte[] { 0x3F, 0xFF }, 256
                    ); 
                    ISO7816.Response response4 = session.SendCommand(
                        0x00, 0xA4, 0x01, 0x01, new byte[] { 0x3F, 0xFF }, 256
                    ); 
                    // получить имя производителя
                    byte[] encoded = session.GetAttribute(API.SCARD_ATTR_VENDOR_NAME);
               
                    // раскодировать имя производителя
                    try { manufacturer = System.Text.Encoding.UTF8.GetString(encoded); }

                    // указать шестнадцатеричное представление
                    catch { manufacturer = Arrays.ToHexString(encoded); }
                }
                catch {} try {
                    // получить название модели
                    byte[] encoded = session.GetAttribute(API.SCARD_ATTR_VENDOR_IFD_TYPE);

                    // раскодировать название модели
                    try { model = System.Text.Encoding.UTF8.GetString(encoded); }

                    // указать шестнадцатеричное представление
                    catch { model = Arrays.ToHexString(encoded); }
                }
                catch {} try {  
                    // получить номер версии
                    byte[] encoded = session.GetAttribute(API.SCARD_ATTR_VENDOR_IFD_VERSION);

                    // проверить корректность размера 
                    if (encoded.Length != 4) version = null; 

                    // сохранить номер версии
                    version = new Version(encoded[3], encoded[2], (encoded[1] << 8) | encoded[0]); 
                }
                // обработать возможную ошибку
                catch {} try { 
                    // получить серийный номер смарт-карты
                    serial = session.GetAttribute(API.SCARD_ATTR_VENDOR_IFD_SERIAL_NO); 
                }
                // обработать возможную ошибку
                catch {}
            }
        }
		// считыватель 
        public IReader Reader { get { return reader; }} 

        // атрибуты смарт-карты
        public string  Manufacturer { get { return manufacturer; }}
        public string  Model        { get { return model;        }}
        public Version Version      { get { return version;      }}
        public byte[]  Serial       { get { return serial;       }}
        public byte[]  ATR          { get { return atr;          }} 

        // состояние смарт-карты
        public CardState GetState() 
        { 
	        // создать используемый контекст
	        ulong hContext = module.EstablishContext(scope); 
            try {
                // получить состояние смарт-карты
                return module.GetCardState(hContext, reader.Name); 
            }
            // освободить выделенные ресурсы
            finally { module.ReleaseContext(hContext); }
        }
        // получить атрибут смарт-карты
        public byte[] GetAttribute(uint attrId)
        {
            // указать режим открытия сеанса
            OpenMode openMode = OpenMode.Shared; Protocol protocols = Protocol.T0 | Protocol.T1; 

            // создать сеанс со считывателем
            using (ReaderSession session = reader.CreateSession(openMode, protocols))
            {
                // получить атрибут смарт-карты
                return session.GetAttribute(attrId); 
            }
        }
    }
}
