using System;
using System.IO;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////////
    // Логический канал
    ///////////////////////////////////////////////////////////////////////////////
    public class LogicalChannel : RefObject
    {
        // сеанс взаимодействия со смарт-картой
        private CardEnvironment environment; private CardSession session; private byte ordinal; 
    
        // конструктор
        protected LogicalChannel() 
        {
            // сохранить переданные параметры
            this.environment = null; this.session = null; this.ordinal = 0;
        }
        // конструктор
        private LogicalChannel(CardEnvironment environment, CardSession session, int ordinal)
        {
            // проверить корректность номера
            if (ordinal == 0 || ordinal > 19) throw new ArgumentException(); 
        
            // сохранить переданные параметры
            this.environment = environment; this.ordinal = (byte)ordinal;
            
            // сохранить переданные параметры
            this.session = RefObject.AddRef(session);

            // обработать файл EF.ATR
            this.environment = environment.CombineEFATR(this); 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose() 
        {
            // проверить номер канала
            if (ordinal == 0) { base.OnDispose(); return; }
        
            // закрыть логический канал
            SendCommand(INS.ManageChannel, 0x80, ordinal, new byte[0], 0); 
            
            // освободить выделенные ресурсы
            RefObject.Release(session); base.OnDispose();
        }
        // возможности смарт-карты
        public virtual CardEnvironment Environment { get { return environment; }}
        // сеанс взаимодействия со смарт-картой
        public virtual CardSession Session { get { return session; }}

        // номер канала
        public int Ordinal { get { return ordinal; }}
    
        // создать логический канал
        public LogicalChannel Сreate() 
        {
            // получить требуемый объект
            BER.CardCapabilities cardCapabilities = Environment.CardCapabilities; 

            // при отсутствии объекта
            if (cardCapabilities == null || cardCapabilities.Content.Length < 3)
            {
                // при ошибке выбросить исключение
                throw new ResponseException(0x6881); 
            }
            // приверить поддержку создания каналов
            if ((cardCapabilities.Data(2) & 0x18) == 0) 
            {
                // при ошибке выбросить исключение
                throw new ResponseException(0x6881); 
            }
            // при поддержке создания динамического канала
            if ((cardCapabilities.Data(2) & 0x08) != 0)
            {
                // открыть логический канал
                Response response = SendCommand( 
                    INS.ManageChannel, 0x00, 0x00, new byte[0], 1
                ); 
                // проверить отсутствие ошибок
                ResponseException.Check(response);
        
                // проверить размер поля
                if (response.Data.Length != 1) throw new InvalidDataException(); 
        
                // вернуть объект канала
                return new LogicalChannel(Environment, Session, response.Data[0]); 
            }
            // при поддержке создания каналов
            if ((cardCapabilities.Data(2) & 0x10) != 0)
            {
                // определить число каналов
                int channels = (cardCapabilities.Data(2) & 0x07); 
            
                // скорректировать число каналов
                channels = (channels == 7) ? 20 : (channels + 1); 
            
                // для всех каналов
                for (byte i = 1; i < channels; i++)
                {
                    // создать логический канал
                    Response response = SendCommand(  
                        INS.ManageChannel, 0x00, i, new byte[0], 0
                    ); 
                    // проверить отсутствие ошибок
                    if (!Response.Error(response))
                    {
                        // вернуть объект канала
                        return new LogicalChannel(Environment, Session, i); 
                    }
                }
            }
            // при ошибке выбросить исключение
            throw new IOException(); 
        }
        // открыть логический канал
        public LogicalChannel Сreate(byte ordinal)
        {
            // проверить корректность параметров
            if (ordinal <= 0 || ordinal > 19) throw new ArgumentException(); 
        
            // получить требуемый объект
            BER.CardCapabilities cardCapabilities = Environment.CardCapabilities; 

            // при отсутствии объекта
            if (cardCapabilities == null || cardCapabilities.Content.Length < 3)
            {
                // при ошибке выбросить исключение
                throw new ResponseException(0x6881); 
            }
            // приверить поддержку создания каналов
            if ((cardCapabilities.Data(2) & 0x18) == 0) throw new ResponseException(0x6881); 
            if ((cardCapabilities.Data(2) & 0x10) == 0) throw new ResponseException(0x6A81); 

            // открыть логический канал
            Response response = SendCommand( 
                INS.ManageChannel, 0x00, ordinal, new byte[0], 0
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response);
        
            // вернуть объект канала
            return new LogicalChannel(Environment, Session, ordinal); 
        }
        // выполнить команду
	    public Response SendCommand(byte ins, byte p1, byte p2, byte[] data, int ne)
        {
            // выполнить команду
            return SendCommand(SecureType.None, null, ins, p1, p2, data, ne); 
        }
        // выполнить команду
	    public Response SendCommand(SecureType secureType, 
            SecureClient secureClient, byte ins, byte p1, byte p2, byte[] data, int ne) 
        {
            // для первых каналов
            byte cla = 0; if (ordinal <= 3) cla = (byte)(ordinal | (((int)secureType & 0x3) << 2)); 

            else switch (secureType & SecureType.SecureHeader)
            {
            // указать класс команды
            case SecureType.None        : cla = (byte)((ordinal - 4) | 0x40); break; 
            case SecureType.Secure      : cla = (byte)((ordinal - 4) | 0x60); break; 
            case SecureType.SecureHeader: cla = (byte)((ordinal - 4) | 0x60); break; 

            // обработать возможную ошибку
            default: return new Response(new byte[0], 0x6A81); 
            }
            // при отсутствии защиты
            if (secureClient == null || secureType == SecureType.None || secureType == SecureType.Proprietary)
            {
                // выполнить команду
                return Environment.SendCommand(Session, cla, ins, p1, p2, data, ne); 
            }
            else {
                // указать криптографическую среду
                SecurityEnvironment securityEnvironment = SecurityEnvironment.Current; 
            
                // получить параметры алгоритмов
                BER.CRT.CT  cipherParameters = securityEnvironment.GetCipherParameters(this); 
                BER.CRT.CCT    macParameters = securityEnvironment.GetMacParameters   (this); 
                BER.CRT.DST   signParameters = securityEnvironment.GetSignParameters  (this); 
            
                // выполнить защиту сообщения
                data = secureClient.Protect(Environment, secureType,  
                    cipherParameters, macParameters, signParameters, cla, ins, p1, p2, data, ne
                ); 
                // выполнить команду
                Response response = Environment.SendCommand(Session, cla, ins, p1, p2, data, -1); 
            
                // снять защиту сообщения
                return secureClient.Unprotect(Environment, 
                    cipherParameters, macParameters, signParameters, response
                ); 
            }
        }
        // выполнить команду
	    public Response SendChainCommand(byte ins, byte p1, byte p2, byte[] data)
        {
            // выполнить команду
            return SendChainCommand(SecureType.None, null, ins, p1, p2, data); 
        }
        // выполнить команду
	    public Response SendChainCommand(SecureType secureType, 
            SecureClient secureClient, byte ins, byte p1, byte p2, byte[] data)
        {
            // для первых каналов
            byte cla = 0; if (ordinal <= 3) cla = (byte)(ordinal | 0x10 | (((int)secureType & 0x3) << 2)); 

            else switch (secureType & SecureType.SecureHeader)
            {
            // указать класс команды
            case SecureType.None        : cla = (byte)((ordinal - 4) | 0x50); break; 
            case SecureType.Secure      : cla = (byte)((ordinal - 4) | 0x70); break; 
            case SecureType.SecureHeader: cla = (byte)((ordinal - 4) | 0x70); break; 

            // обработать возможную ошибку
            default: return new Response(new byte[0], 0x6A81); 
            }
            // при отсутствии защиты
            if (secureClient == null || secureType == SecureType.None || secureType == SecureType.Proprietary)
            {
                // выполнить команду
                return Environment.SendCommand(Session, cla, ins, p1, p2, data, 0); 
            }
            else {
                // указать криптографическую среду
                SecurityEnvironment securityEnvironment = SecurityEnvironment.Current; 
            
                // получить параметры алгоритмов
                BER.CRT.CT  cipherParameters = securityEnvironment.GetCipherParameters(this); 
                BER.CRT.CCT    macParameters = securityEnvironment.GetMacParameters   (this); 
                BER.CRT.DST   signParameters = securityEnvironment.GetSignParameters  (this); 
            
                // выполнить защиту сообщения
                data = secureClient.Protect(Environment, secureType,   
                    cipherParameters, macParameters, signParameters, cla, ins, p1, p2, data, 0
                ); 
                // выполнить команду
                Response response = Environment.SendCommand(Session, cla, ins, p1, p2, data, -1); 
            
                // снять защиту сообщения
                return secureClient.Unprotect(Environment, 
                    cipherParameters, macParameters, signParameters, response
                ); 
            }
        }
    }
}
