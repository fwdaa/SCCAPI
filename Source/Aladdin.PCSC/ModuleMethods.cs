using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Permissions;
using System.Runtime.InteropServices;

namespace Aladdin.PCSC
{
    ///////////////////////////////////////////////////////////////////////////
    // Реализация интерфейса PC/SC
    ///////////////////////////////////////////////////////////////////////////
    public class ModuleMethods : Module
    {
        ///////////////////////////////////////////////////////////////////////
        // Контекст диспетчера смарт-карт
        ///////////////////////////////////////////////////////////////////////

        // создать контекст
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public override ulong EstablishContext(ReaderScope scope) 
        { 
            // закодировать область видимости
            UIntPtr hContext; uint dwScope = Encoding.EncodeScope(scope); 
            
            // создать контекст
            Exception.Check(NativeMethods.SCardEstablishContext(
                dwScope, IntPtr.Zero, IntPtr.Zero, out hContext
            )); 
            // вернуть описатель контекста
            return hContext.ToUInt64(); 
        }
        // закрыть контекст
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public override void ReleaseContext(ulong hContext) 
        {
            // закрыть контекст
            Exception.Check(NativeMethods.SCardReleaseContext(
                new UIntPtr(hContext)
            )); 
        }
        ///////////////////////////////////////////////////////////////////////
        // Управление группами считывателй
        ///////////////////////////////////////////////////////////////////////

        // перечислить группы считывателей
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public override string[] ListReaderGroups(ulong hContext) 
        { 
            // указать признак автоматического выделения памяти
            IntPtr ptr; int cchGroups = API.SCARD_AUTOALLOCATE; 

            // перечислить группы считывателей
            Exception.Check(NativeMethods.SCardListReaderGroups(
                new UIntPtr(hContext), out ptr, ref cchGroups
            )); 
            try {
                // извлечь мультистроку
                string multiString = Marshal.PtrToStringUni(ptr, cchGroups); 

                // раскодировать мультистроку
                return Encoding.DecodeMultiString(multiString); 
            }
            // освободить выделенную память
            finally { NativeMethods.SCardFreeMemory(new UIntPtr(hContext), ptr); }
        }
        ///////////////////////////////////////////////////////////////////////
        // Перечисление считывателей
        ///////////////////////////////////////////////////////////////////////

        // перечислить считыватели
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public override string[] ListReaders(ulong hContext, string[] groups)
        {
            // указать признак автоматического выделения памяти
            IntPtr ptr; int cchReaders = API.SCARD_AUTOALLOCATE; 

            // закодировать мультистроку
            string multiGroups = Encoding.EncodeMultiString(groups); 

            // перечислить группы считывателей
            uint code = NativeMethods.SCardListReaders(
                new UIntPtr(hContext), multiGroups, out ptr, ref cchReaders
            ); 
            // проверить код ошибки 
            if (code == API.SCARD_E_NO_READERS_AVAILABLE) return new string[0]; 

            // проверить код ошибки 
            else Exception.Check(code); 
            try {
                // извлечь мультистроку
                string multiString = Marshal.PtrToStringUni(ptr, cchReaders); 

                // раскодировать мультистроку
                return Encoding.DecodeMultiString(multiString); 
            }
            // освободить выделенную память
            finally { NativeMethods.SCardFreeMemory(new UIntPtr(hContext), ptr); }
        }
	    // состояние считывателя
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
	    public override uint GetState(ulong hContext, string readerName)
        {
	        // выделить список информации о считывателях
	        NativeMethods.SCARD_READERSTATE[] states = 
                new NativeMethods.SCARD_READERSTATE[1]; 
        
            // указать имя считывателя
	        states[0].szReader = readerName; states[0].pvUserData = IntPtr.Zero; 
                    
            // указать неизвестное состояние
            states[0].dwCurrentState = API.SCARD_STATE_UNAWARE; 
            states[0].dwEventState   = API.SCARD_STATE_UNAWARE; 

            // обнулить ATR
            states[0].rgbAtr = new byte[36]; states[0].cbAtr = 0; 

	        // получить информацию о состоянии считывателей
            uint code = NativeMethods.SCardGetStatusChange(
                new UIntPtr(hContext), 0, states, states.Length
            ); 
            // вернуть состояние считывателя
            return (code == API.SCARD_S_SUCCESS) ? states[0].dwEventState : 0; 
        }
	    // функция прослушивания считывателей
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
	    public override uint ListenReaders(ulong hContext, IReaderHandler readerHandler) 
        {
	        // заново перечислить считыватели
	        string[] readers = readerHandler.ListReaders(hContext); 

            // создать список имен считывателей
            List<String> names = new List<String>(readers); 

	        // выделить список информации о считывателях
	        NativeMethods.SCARD_READERSTATE[] states = 
                new NativeMethods.SCARD_READERSTATE[readers.Length + 1]; 

	        // указать имя специального считывателя
            states[0].szReader = "\\\\?PnP?\\Notification"; states[0].pvUserData = IntPtr.Zero; 

            // указать неизвестное состояние
            states[0].dwCurrentState = API.SCARD_STATE_UNAWARE; 
            states[0].dwEventState   = API.SCARD_STATE_UNAWARE; 

            // обнулить ATR
            states[0].rgbAtr = new byte[36]; states[0].cbAtr = 0; 

	        // для всех считывателей
	        for (int i = 0; i < readers.Length; i++) 
	        {
	            // указать имя считывателя
		        states[i + 1].szReader = readers[i]; states[i + 1].pvUserData = IntPtr.Zero; 
                    
                // указать неизвестное состояние
                states[i + 1].dwCurrentState = API.SCARD_STATE_UNAWARE; 
                states[i + 1].dwEventState   = API.SCARD_STATE_UNAWARE; 

                // обнулить ATR
                states[i + 1].rgbAtr = new byte[36]; states[i + 1].cbAtr = 0; 
            }
	        // получить информацию о состоянии считывателей
            uint code = NativeMethods.SCardGetStatusChange(
                new UIntPtr(hContext), 0, states, states.Length
            ); 
            // проверить отсутствие ошибок
            if (code != API.SCARD_S_SUCCESS) return code; 
            
	        // для всех считывателей
            for (int i = 0; i < readers.Length; i++) 
	        {
		        // сохранить новое состояние
		        states[i + 1].dwCurrentState = states[i + 1].dwEventState; 
			
		        // сбросить состояние изменения
		        states[i + 1].dwCurrentState &= ~API.SCARD_STATE_CHANGED; 
	        }
	        // получить информацию о состоянии считывателей
	        code = NativeMethods.SCardGetStatusChange(
                new UIntPtr(hContext), UInt32.MaxValue, states, states.Length
            ); 
	        // при отсутствии ошибок
            for (string[] newReaders = readers; code == API.SCARD_S_SUCCESS; newReaders = readers) 
            { 
		        // при изменении числа считывателей
		        while (code == API.SCARD_S_SUCCESS && (states[0].dwEventState & API.SCARD_STATE_CHANGED) != 0)
		        {
			        // сбросить состояние изменения
			        states[0].dwCurrentState &= ~API.SCARD_STATE_CHANGED; 

			        // сохранить новое состояние
			        states[0].dwCurrentState = states[0].dwEventState; 
			
			        // заново перечислить считыватели
			        newReaders = readerHandler.ListReaders(hContext); 

			        // для всех заново перечисленных считывателей
			        for (int i = 0; i < newReaders.Length; i++) 
			        {
				        // проверить появление нового считывателя
				        if (names.Contains(newReaders[i])) continue; names.Add(newReaders[i]);

				        // изменить список считывателей
				        Array.Resize(ref readers, readers.Length + 1); 

				        // сохранить имя нового считывателя
				        readers[readers.Length - 1] = newReaders[i]; 

				        // увеличить список информации о считывателях
				        Array.Resize(ref states, states.Length + 1); 

				        // указать имя нового считывателя
				        states[states.Length - 1].szReader = newReaders[i]; 
                        states[states.Length - 1].pvUserData = IntPtr.Zero; 

                        // указать неизвестное состояние
                        states[states.Length - 1].dwCurrentState = API.SCARD_STATE_UNAWARE; 
                        states[states.Length - 1].dwEventState   = API.SCARD_STATE_UNAWARE; 

                        // обнулить ATR
                        states[states.Length - 1].rgbAtr = new byte[36]; 
                        states[states.Length - 1].cbAtr  = 0; 
			        }
			        // получить информацию о состоянии считывателей
			        code = NativeMethods.SCardGetStatusChange(
                        new UIntPtr(hContext), UInt32.MaxValue, states, states.Length
                    ); 
		        }
		        // проверить отсутствие ошибок
		        if (code != API.SCARD_S_SUCCESS) break; 
                
		        // для всех считывателей
                for (int i = 0; i < readers.Length; i++) 
		        {  
			        // проверить тип смарт-карты
			        if ((states[i + 1].dwCurrentState & API.SCARD_STATE_IGNORE) != 0) continue; 

			        // проверить изменение состояния
			        if ((states[i + 1].dwEventState & API.SCARD_STATE_CHANGED) == 0) continue; 

		            // сбросить состояние изменения
		            states[i + 1].dwCurrentState &= ~API.SCARD_STATE_CHANGED; 

			        // при отсутствующем считывателе
			        if ((states[i + 1].dwEventState & API.SCARD_STATE_UNKNOWN    ) != 0 ||
				        (states[i + 1].dwEventState & API.SCARD_STATE_UNAVAILABLE) != 0) 
			        {
				        // при присутствовавшей смарт-карте
				        if ((states[i + 1].dwCurrentState & API.SCARD_STATE_PRESENT) != 0)
				        {
				            // уведомить о произошедшем событии
				            try { readerHandler.OnRemoveCard(hContext, readers[i]); } catch {}
				        }
				        // при присутствовавшем считывателе
				        if ((states[i + 1].dwCurrentState & API.SCARD_STATE_UNKNOWN    ) == 0 && 
				            (states[i + 1].dwCurrentState & API.SCARD_STATE_UNAVAILABLE) == 0)
				        {
				            // уведомить о произошедшем событии
				            try { readerHandler.OnRemoveReader(hContext, readers[i]); } catch {}
				        }
			        }
			        // при отсутствующей смарт-карте
			        else if ((states[i + 1].dwEventState & API.SCARD_STATE_EMPTY) != 0)
			        {
				        // при отсутствовавшем считывателе
				        if ((states[i + 1].dwCurrentState == API.SCARD_STATE_UNAWARE    )      ||
					        (states[i + 1].dwCurrentState &  API.SCARD_STATE_UNKNOWN    ) != 0 || 
				            (states[i + 1].dwCurrentState &  API.SCARD_STATE_UNAVAILABLE) != 0)
				        {
				            // уведомить о произошедшем событии
				            try { readerHandler.OnInsertReader(hContext, readers[i]); } catch {}
				        }
				        // при присутствовавшей смарт-карте
				        else if ((states[i + 1].dwCurrentState & API.SCARD_STATE_PRESENT) != 0)
				        {
				            // уведомить о произошедшем событии
				            try { readerHandler.OnRemoveCard(hContext, readers[i]); } catch {}
				        }
			        }
			        // при присутствующей смарт-карте
			        else if ((states[i + 1].dwEventState & API.SCARD_STATE_PRESENT) != 0)
			        {
				        // при отсутствовавшем считывателе
				        if ((states[i + 1].dwCurrentState == API.SCARD_STATE_UNAWARE    )      ||
					        (states[i + 1].dwCurrentState &  API.SCARD_STATE_UNKNOWN    ) != 0 || 
				            (states[i + 1].dwCurrentState &  API.SCARD_STATE_UNAVAILABLE) != 0)
				        {
				            // уведомить о произошедшем событии
				            try { readerHandler.OnInsertReader(hContext, readers[i]); } catch {}

				            // уведомить о произошедшем событии
				            try { readerHandler.OnInsertCard(hContext, readers[i]); } catch {}
                        }
				        // при отсутствовавшей смарт-карте
				        else if ((states[i + 1].dwCurrentState & API.SCARD_STATE_EMPTY) != 0)
				        {
				            // уведомить о произошедшем событии
				            try { readerHandler.OnInsertCard(hContext, readers[i]); } catch {}
				        }
			        }
		            // сохранить новое состояние
		            states[i + 1].dwCurrentState = states[i + 1].dwEventState; 
		        }
		        // при изменении числа считывателей
		        if (newReaders.Length != readers.Length)
		        {
			        // выделить память для информации о считывателях
			        NativeMethods.SCARD_READERSTATE[] newReaderStates = 
                        new NativeMethods.SCARD_READERSTATE[newReaders.Length + 1]; 
			
			        // скопировать состояние
			        newReaderStates[0] = states[0]; 

			        // для всех заново перечисленных считывателей
			        for (int i = 0; i < newReaders.Length; i++) 
			        {
				        // найти считыватель в списке
				        int index = names.IndexOf(newReaders[i]); 

				        // скопировать состояние
				        newReaderStates[i + 1] = states[index + 1]; 
			        }
			        // переустановить имена считывателей
                    names.Clear(); names.AddRange(newReaders); 

			        // переустановить список информации
			        readers = newReaders; states = newReaderStates; 
		        }
    	        // получить информацию о состоянии считывателей
		        code = NativeMethods.SCardGetStatusChange(
                    new UIntPtr(hContext), UInt32.MaxValue, states, states.Length
                ); 
            }
            return code; 
        }
        // отменить ожидание события смарт-карт
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public override void CancelContext(ulong hContext) 
        {
            // отменить ожидание события смарт-карт
            Exception.Check(NativeMethods.SCardCancel(new UIntPtr(hContext))); 
        } 
        ///////////////////////////////////////////////////////////////////////
        // Управление считывателями и смарт-картами
        ///////////////////////////////////////////////////////////////////////

        // открыть считыватель и смарт-карту
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public override ulong Connect(ulong hContext,
            string reader, OpenMode openMode, ref Protocol protocols) 
        { 
            // преобразовать режим открытия
            UIntPtr hCard; uint dwShareMode = Encoding.EncodeOpenMode(openMode); 

            // закодировать предпочтительные протоколы
            uint dwProtocols = Encoding.EncodeProtocol(protocols); 

            // открыть считыватель и смарт-карту
            Exception.Check(NativeMethods.SCardConnect(
                new UIntPtr(hContext), reader, 
                dwShareMode, dwProtocols, out hCard, out dwProtocols
            )); 
            // раскодировать используемый протокол
            protocols = Encoding.DecodeProtocol(dwProtocols); return hCard.ToUInt64();
        }
        // заново открыть считыватель и смарт-карту
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public override void Reconnect(ulong hCard, CloseMode closeMode, 
            OpenMode openMode, ref Protocol protocols) 
        {
            // проверить корректность параметров
            if (closeMode == CloseMode.Eject) throw new ArgumentException(); 

            // преобразовать режим закрытия
            uint dwCloseMode = Encoding.EncodeCloseMode(closeMode); 

            // преобразовать режим открытия
            uint dwShareMode = Encoding.EncodeOpenMode(openMode); 

            // закодировать предпочтительные протоколы
            uint dwProtocols = Encoding.EncodeProtocol(protocols); 

            // заново открыть считыватель и смарт-карту
            Exception.Check(NativeMethods.SCardReconnect(
                new UIntPtr(hCard), dwShareMode, 
                dwProtocols, dwCloseMode, out dwProtocols
            )); 
            // раскодировать используемый протокол
            protocols = Encoding.DecodeProtocol(dwProtocols);
        }
        // закрыть считыватель и смарт-карту
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public override void Disconnect(ulong hCard, CloseMode closeMode) 
        {
            // выполнить преобразование типа
            uint dwCloseMode = Encoding.EncodeCloseMode(closeMode); 

            // закрыть считыватель и смарт-карту
            Exception.Check(NativeMethods.SCardDisconnect(
                new UIntPtr(hCard), dwCloseMode
            )); 
        }
        // получить состояние считывателя и смарт-карты
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public override ReaderStatus GetReaderStatus(ulong hCard)
        {
            // инициализировать переменные
            ReaderStatus status; status.state = 0; int cchReaderLen = 0;

            // инициализировать переменные
            uint dwProtocol = API.SCARD_PROTOCOL_UNDEFINED; 

            // выделить память для ATR
            int cbAtrLen = 32; status.atr = new byte[cbAtrLen]; 

            // определить требуемый размер данных
            Exception.Check(NativeMethods.SCardStatus(
                new UIntPtr(hCard), IntPtr.Zero, ref cchReaderLen, 
                out status.state, out dwProtocol, status.atr, ref cbAtrLen
            ));
            // выделить буфер требуемого размера
            IntPtr ptr = Marshal.AllocHGlobal(cchReaderLen); 
            try { 
                // получить информацию считывателя
                uint code = NativeMethods.SCardStatus(
                    new UIntPtr(hCard), ptr, ref cchReaderLen, 
                    out status.state, out dwProtocol, status.atr, ref cbAtrLen
                );
                // проверить отсутствие ошибок
                if (code != API.SCARD_S_SUCCESS && code != API.SCARD_E_INSUFFICIENT_BUFFER)
                {
                    // при ошибке выбросить исключение
                    Exception.Check(code); 
                }
                // извлечь мультистроку
                string multiString = Marshal.PtrToStringUni(ptr, cchReaderLen); 

                // раскодировать имена считывателей
                status.readers = Encoding.DecodeMultiString(multiString); 

                // раскодировать используемый протокол
                status.protocol = Encoding.DecodeProtocol(dwProtocol); 

                // изменить размер ATR
                Array.Resize(ref status.atr, cbAtrLen); return status; 
            }
            // освободить выделенную память
            finally { Marshal.FreeHGlobal(ptr); }
        }
        // получить атрибут считывателя
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public override byte[] GetReaderAttribute(ulong hCard, uint atrId) 
        { 
            int cbAttrLen = 0; 

            // определить требуемый размер буфера
            Exception.Check(NativeMethods.SCardGetAttrib(
                new UIntPtr(hCard), atrId, null, ref cbAttrLen
            ));
            // выделить буфер требуемого размера
            byte[] attr = new byte[cbAttrLen]; 

            // получить атрибут считывателя
            Exception.Check(NativeMethods.SCardGetAttrib(
                new UIntPtr(hCard), atrId, attr, ref cbAttrLen
            ));
            // изменить размер атрибута
            Array.Resize(ref attr, cbAttrLen); return attr; 
        }
        // установить атрибут считывателя
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public override void SetReaderAttribute(ulong hCard, uint atrId, byte[] attr) 
        {
            // установить атрибут считывателя
            Exception.Check(NativeMethods.SCardSetAttrib(
                new UIntPtr(hCard), atrId, attr, attr.Length
            ));
        }
        // начать транзакцию со смарт-картой
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public override void BeginTransaction(ulong hCard) 
        {
            // начать транзакцию со смарт-картой
            Exception.Check(NativeMethods.SCardBeginTransaction(new UIntPtr(hCard)));
        } 
        // завершить транзакцию со смарт-картой
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public override void EndTransaction(ulong hCard, CloseMode closeMode) 
        {
            // выполнить преобразование типа
            uint dwCloseMode = Encoding.EncodeCloseMode(closeMode); 

            // завершить транзакцию со смарт-картой
            Exception.Check(NativeMethods.SCardEndTransaction(
                new UIntPtr(hCard), dwCloseMode
            ));
        } 
        // передать команду считывателю
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public override byte[] SendControl(ulong hCard, 
            uint controlCode, byte[] inBuffer, int maxOutBufferSize)
        {
            // указать максимальный размер выходного буфера
            int cbOutBufferSize = maxOutBufferSize; 
            
            // выделить буфер требуемого размера
            byte[] outBuffer = new byte[cbOutBufferSize]; 

            // передать команду считывателю
            Exception.Check(NativeMethods.SCardControl(
                new UIntPtr(hCard), controlCode, inBuffer, inBuffer.Length, 
                outBuffer, maxOutBufferSize, out cbOutBufferSize
            ));
            // изменить размер буфера
            Array.Resize(ref outBuffer, cbOutBufferSize); return outBuffer; 
        }
        // передать команду смарт-карте
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public override byte[] SendCommand(ulong hCard, 
            Protocol protocol, byte[] sendBuffer, int maxRecvLength)
        {
            // выделить требуемую структуру
            NativeMethods.SCARD_IO_REQUEST request; request.cbPciLength = 0; 
            
            // закодировать используемый протокол
            request.dwProtocol = Encoding.EncodeProtocol(protocol); 

            // указать размер структуры
            request.cbPciLength = Marshal.SizeOf(request); 

            // выделить буфер требуемого размера
            int cbRecvLength = maxRecvLength; byte[] recvBuffer = new byte[cbRecvLength]; 

            // передать команду смарт-карте
            Exception.Check(NativeMethods.SCardTransmit(
                new UIntPtr(hCard), ref request, sendBuffer, sendBuffer.Length, 
                ref request, recvBuffer, ref cbRecvLength
            ));
            // изменить размер буфера
            Array.Resize(ref recvBuffer, cbRecvLength); return recvBuffer; 
        }
    }
}
