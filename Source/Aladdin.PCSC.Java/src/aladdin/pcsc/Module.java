package aladdin.pcsc;
import aladdin.*; 
import java.io.*; 
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Модуль библиотеки PKCS11
///////////////////////////////////////////////////////////////////////////
public final class Module extends Disposable
{
	// используемый модуль
	private final Wrapper library; 
	
	// конструктор/деструктор
	public Module() throws IOException 
	{
		// загрузить модуль PC/SC
		library = new Wrapper(); 
	}
    // освободить выделенные ресурсы
	@Override protected void onClose() throws IOException
    { 
        library.close(); super.onClose(); 
    } 
    // создать контекст
    public long establishContext(ReaderScope scope) throws Exception
    {
        // создать контекст
        return library.establishContext(scope.value()); 
    }
    // закрыть контекст
    public void releaseContext(long hContext) throws Exception
    {
        // закрыть контекст
        library.releaseContext(hContext);
    }
    // перечислить группы считывателей
    public String[] listReaderGroups(long hContext) throws Exception
    {
        // перечислить группы считывателей
        return library.listReaderGroups(hContext); 
    }
    // перечислить считыватели
    public String[] listReaders(long hContext, String[] groups) throws Exception
    {
        // перечислить считыватели
        return library.listReaders(hContext, groups); 
    }
    // дождаться события смарт-карт
    public int getStatusChange(long hContext, 
        int timeout, ReaderAndState[] readerStates) throws Exception
    {
        // дождаться события смарт-карт
        return library.getStatusChange(hContext, timeout, readerStates); 
    }
    // состояние считывателя
    public int getState(long hContext, String readerName)
    {
        // указать отсутствие информации о состоянии
        ReaderAndState[] states = new ReaderAndState[] {
            new ReaderAndState(readerName, API.SCARD_STATE_UNAWARE)
        }; 
        try {
            // получить информацию о состоянии
            int code = getStatusChange(hContext, 0, states); 
            
            // вернуть состояние считывателя
            return (code == API.SCARD_S_SUCCESS) ? states[0].eventState : 0; 
        }
        // освободить выделенные ресурсы
        catch (Throwable e) {} return 0;
    }
	// состояние считывателя
	public ReaderState getReaderState(long hContext, String readerName) 
    {
        // получить информацию о состоянии
        int state = getState(hContext, readerName); 

        // проверить состояние считывателя
        if ((state & API.SCARD_STATE_PRESENT) != 0) return ReaderState.CARD; 
        if ((state & API.SCARD_STATE_EMPTY  ) != 0) return ReaderState.EMPTY; 
        if ((state & API.SCARD_STATE_UNKNOWN) != 0) return ReaderState.UNKNOWN; 
        
        // вернуть значение по умолчанию
        return ReaderState.UNAVAILABLE;
    }
    // состояние смарт-карты
    public CardState getCardState(long hContext, String readerName)
    {
        // получить информацию о состоянии
        int state = getState(hContext, readerName); 
        
        // проверить состояние считывателя
        if ((state & API.SCARD_STATE_MUTE     ) != 0) return CardState.MUTE; 
        if ((state & API.SCARD_STATE_EXCLUSIVE) != 0) return CardState.EXCLUSIVE; 
        if ((state & API.SCARD_STATE_INUSE    ) != 0) return CardState.SHARED; 
	    if ((state & API.SCARD_STATE_PRESENT  ) != 0) return CardState.PRESENT;
        
        // вернуть значение по умолчанию
        return CardState.EMPTY; 
    }
	// функция прослушивания считывателей
	public int listenReaders(long hContext, IReaderHandler readerHandler) throws IOException
    {
	    // заново перечислить считыватели
	    String[] readers = readerHandler.listReaders(hContext); 

        // создать список имен считывателей
        List<String> names = new ArrayList<String>(Arrays.asList(readers)); 

	    // выделить список информации о считывателях
	    ReaderAndState[] readerStates = new ReaderAndState[readers.length + 1]; 
        
        // указать имя специального считывателя с неизвестным состоянием
	    readerStates[0] = new ReaderAndState("\\\\?PnP?\\Notification",  API.SCARD_STATE_UNAWARE); 

	    // для всех считывателей
	    for (int i = 0; i < readers.length; i++) 
	    {
            // указать имя считывателя с неизвестным состоянием
		    readerStates[i + 1] = new ReaderAndState(names.get(i), API.SCARD_STATE_UNAWARE); 
	    }
        // получить информацию о состоянии считывателей
        int code = getStatusChange(hContext, 0, readerStates); 
        
        // проверить отсутствие ошибок
        if (code != API.SCARD_S_SUCCESS) return code; 

	    // для всех считывателей
	    for (int i = 0; i < readers.length; i++) 
	    {
		    // сохранить новое состояние
		    readerStates[i + 1].currentState = readerStates[i + 1].eventState; 
			
		    // сбросить состояние изменения
		    readerStates[i + 1].currentState &= ~API.SCARD_STATE_CHANGED; 
	    }
        // получить информацию о состоянии считывателей
	    code = getStatusChange(hContext, -1, readerStates); 
        
        // при отсутствии ошибок
        while (code == API.SCARD_S_SUCCESS) { String[] newReaders = readers; 
         
		    // при изменении числа считывателей
		    while (code == API.SCARD_S_SUCCESS && (readerStates[0].eventState & API.SCARD_STATE_CHANGED) != 0)
		    {
		        // сбросить состояние изменения
		        readerStates[0].currentState &= ~API.SCARD_STATE_CHANGED; 
                
		        // сохранить новое состояние
		        readerStates[0].currentState = readerStates[0].eventState; 
			
		        // заново перечислить считыватели
		        newReaders = readerHandler.listReaders(hContext); 

		        // для всех заново перечисленных считывателей
		        for (int i = 0; i < newReaders.length; i++) 
		        {
			        // проверить появление нового считывателя
			        if (names.contains(newReaders[i])) continue; names.add(newReaders[i]);

		            // изменить список считывателей
			        readers = Arrays.copyOf(readers, readers.length + 1); 

			        // сохранить имя нового считывателя
			        readers[readers.length - 1] = newReaders[i]; 

			        // увеличить список информации о считывателях
			        readerStates = Arrays.copyOf(readerStates, readerStates.length + 1); 

                    // указать неизвестное состояние нового считывателя
                    ReaderAndState readerState = new ReaderAndState(
                        newReaders[i], API.SCARD_STATE_UNAWARE
                    ); 
			        // добавить структуру нового считывателя
			        readerStates[readerStates.length - 1] = readerState; 
                }
			    // получить информацию о состоянии считывателей
			    code = getStatusChange(hContext, -1, readerStates); 
		    }
            // проверить отсутствие ошибок
	        if (code != API.SCARD_S_SUCCESS) break; 
            
		    // для всех считывателей
		    for (int i = 0; i < readers.length; i++) 
		    {  
			    // проверить тип смарт-карты
			    if ((readerStates[i + 1].currentState & API.SCARD_STATE_IGNORE) != 0) continue; 

			    // проверить изменение состояния
			    if ((readerStates[i + 1].eventState & API.SCARD_STATE_CHANGED) == 0) continue; 

	            // сбросить состояние изменения
	            readerStates[i + 1].currentState &= ~API.SCARD_STATE_CHANGED; 
                
			    // при отсутствующем считывателе
			    if ((readerStates[i + 1].eventState & API.SCARD_STATE_UNKNOWN    ) != 0 ||
			        (readerStates[i + 1].eventState & API.SCARD_STATE_UNAVAILABLE) != 0) 
			    {
			        // при присутствовавшей смарт-карте
			        if ((readerStates[i + 1].currentState & API.SCARD_STATE_PRESENT) != 0)
			        {
			            // уведомить о произошедшем событии
			            try { readerHandler.onRemoveCard(hContext, readers[i]); } catch (Throwable e) {}
    		        }
			        // при присутствовавшем считывателе
			        if ((readerStates[i + 1].currentState & API.SCARD_STATE_UNKNOWN    ) == 0 && 
			            (readerStates[i + 1].currentState & API.SCARD_STATE_UNAVAILABLE) == 0)
			        {
			            // уведомить о произошедшем событии
			            try { readerHandler.onRemoveReader(hContext, readers[i]); } catch (Throwable e) {}
			        }
			    }
			    // при отсутствующей смарт-карте
			    else if ((readerStates[i + 1].eventState & API.SCARD_STATE_EMPTY) != 0)
			    {
			        // при отсутствовавшем считывателе
			        if ((readerStates[i + 1].currentState == API.SCARD_STATE_UNAWARE    )      ||
				        (readerStates[i + 1].currentState &  API.SCARD_STATE_UNKNOWN    ) != 0 || 
			            (readerStates[i + 1].currentState &  API.SCARD_STATE_UNAVAILABLE) != 0)
			        {
			            // уведомить о произошедшем событии
			            try { readerHandler.onInsertReader(hContext, readers[i]); } catch (Throwable e) {}
    		        }
			        // при присутствовавшей смарт-карте
			        else if ((readerStates[i + 1].currentState & API.SCARD_STATE_PRESENT) != 0)
			        {
			            // уведомить о произошедшем событии
			            try { readerHandler.onRemoveCard(hContext, readers[i]); } catch (Throwable e) {}
			        }
			    }
			    // при присутствующей смарт-карте
			    else if ((readerStates[i + 1].eventState & API.SCARD_STATE_PRESENT) != 0)
			    {
			        // при отсутствовавшем считывателе
			        if ((readerStates[i + 1].currentState == API.SCARD_STATE_UNAWARE    )      ||
				        (readerStates[i + 1].currentState &  API.SCARD_STATE_UNKNOWN    ) != 0 || 
			            (readerStates[i + 1].currentState &  API.SCARD_STATE_UNAVAILABLE) != 0)
			        {
			            // уведомить о произошедшем событии
			            try { readerHandler.onInsertReader(hContext, readers[i]); } catch (Throwable e) {}

			            // уведомить о произошедшем событии
			            try { readerHandler.onInsertCard(hContext, readers[i]); } catch (Throwable e) {}
                    }
			        // при отсутствовавшей смарт-карте
			        else if ((readerStates[i + 1].currentState & API.SCARD_STATE_EMPTY) != 0)
			        {
			            // уведомить о произошедшем событии
			            try { readerHandler.onInsertCard(hContext, readers[i]); } catch (Throwable e) {}
			        }
			    }
	            // сохранить новое состояние
	            readerStates[i + 1].currentState = readerStates[i + 1].eventState; 
		    }
		    // при изменении числа считывателей
		    if (newReaders.length != readers.length)
		    {
			    // выделить память для информации о считывателях
			    ReaderAndState[] newReaderStates = new ReaderAndState[newReaders.length + 1]; 
			
			    // скопировать состояние
			    newReaderStates[0] = readerStates[0]; 
                
			    // для всех заново перечисленных считывателей
			    for (int i = 0; i < newReaders.length; i++) 
			    {
			        // найти считыватель в списке
			        int index = names.indexOf(newReaders[i]); 

			        // скопировать состояние
			        newReaderStates[i + 1] = readerStates[index + 1]; 
			    }
			    // переустановить имена считывателей
                names.clear(); names.addAll(Arrays.asList(newReaders)); 

			    // переустановить список информации
			    readers = newReaders; readerStates = newReaderStates; 
		    }
  	        // получить информацию о состоянии считывателей
	        code = getStatusChange(hContext, -1, readerStates); 
        }
        return code; 
    }
    // отменить ожидание события смарт-карт
    public void cancelContext(long hContext)throws Exception
    {
        // отменить ожидание события смарт-карт
        library.cancelContext(hContext);
    }
    // открыть считыватель и смарт-карту
    public long connect(long hContext, 
        String reader, OpenMode openMode, int[] protocols) throws Exception
    {
        // преобразовать режим открытия
        int dwShareMode = openMode.encode(); 
        
        // закодировать предпочтительные протоколы
        int[] dwProtocols = new int[] { Protocol.encode(protocols[0]) };
        
        // открыть считыватель и смарт-карту
        long hCard = library.connect(hContext, reader, dwShareMode, dwProtocols); 
        
        // указать используемый протокол
        protocols[0] = Protocol.decode(dwProtocols[0]); return hCard; 
    }
    // заново открыть считыватель и смарт-карту
    public void reconnect(long hCard, CloseMode closeMode,
        OpenMode openMode, int[] protocols) throws Exception
    {
        // проверить корректность значения
        if (closeMode == CloseMode.EJECT) throw new IllegalArgumentException(); 
        
        // преобразовать режимы закрытия и открытия
        int dwCloseMode = closeMode.encode(); int dwShareMode = openMode.encode(); 
        
        // закодировать предпочтительные протоколы
        int[] dwProtocols = new int[] { Protocol.encode(protocols[0]) };
        
        // заново открыть считыватель и смарт-карту
        library.reconnect(hCard, dwShareMode, dwProtocols, dwCloseMode);

        // указать используемый протокол
        protocols[0] = Protocol.decode(dwProtocols[0]); 
    }
    // закрыть считыватель и смарт-карту
    public void disconnect(long hCard, CloseMode closeMode) throws Exception
    {
        // закрыть считыватель и смарт-карту
        library.disconnect(hCard, closeMode.encode());
    }
    // получить состояние считывателя и смарт-карты
    public ReaderStatus getReaderStatus(long hCard) throws Exception
    {
        // выделить память для информации
        ReaderStatus readerStatus = new ReaderStatus(); 
        
        // получить состояние считывателя и смарт-карты
        library.getReaderStatus(hCard, readerStatus); 
        
        // раскодировать используемый протокол
        readerStatus.protocol = Protocol.decode(readerStatus.protocol); 
        
        return readerStatus; 
    }
    // получить атрибут считывателя
    public byte[] getReaderAttribute(long hCard, int attrId) throws Exception
    {
        // получить атрибут считывателя
        return library.getReaderAttribute(hCard, attrId); 
    }
    // установить атрибут считывателя
    public void setReaderAttribute(long hCard, int attrId, byte[] attr) throws Exception
    {
        // установить атрибут считывателя
        library.setReaderAttribute(hCard, attrId, attr);
    }
    // начать транзакцию со смарт-картой
    public void beginTransaction(long hCard) throws Exception
    {
        // начать транзакцию со смарт-картой
        library.beginTransaction(hCard);
    }
    // завершить транзакцию со смарт-картой
    public void endTransaction(long hCard, CloseMode closeMode) throws Exception
    {
        // завершить транзакцию со смарт-картой
        library.endTransaction(hCard, closeMode.encode());
    }
    // передать команду считывателю
    public byte[] sendControl(long hCard, 
        int controlCode, byte[] inBuffer, int maxOutBufferSize) throws Exception
    {
        // выделить буфер максимального размера
        byte[] outBuffer = new byte[maxOutBufferSize]; 
        
        // передать команду считывателю
        int outBufferSize = library.control(hCard, controlCode, inBuffer, outBuffer); 
        
        // изменить размер буфера
        return Arrays.copyOf(outBuffer, outBufferSize); 
    }
    // передать команду смарт-карте
    public byte[] sendCommand(long hCard, 
        int protocol, byte[] sendBuffer, int maxRecvLength) throws Exception
    {
        // указать используемый протокол
        int dwProtocol = Protocol.encode(protocol); 
        
        // выделить буфер максимального размера
        byte[] recvBuffer = new byte[maxRecvLength]; 
        
        // передать команду считывателю
        int recvLength = library.transmit(hCard, dwProtocol, sendBuffer, recvBuffer); 
        
        // изменить размер буфера
        return Arrays.copyOf(recvBuffer, recvLength); 
    }
    ///////////////////////////////////////////////////////////////////////
    // Обработчик событий считывателей
    ///////////////////////////////////////////////////////////////////////
    public static interface IReaderHandler
    {
        // перечислить считыватели
        String[] listReaders(long hContext) throws IOException; 

        // добавление считывателя
        void onInsertReader(long hContext, String reader) throws java.lang.Exception;
        // удаление считывателя
        void onRemoveReader(long hContext, String reader) throws java.lang.Exception; 

        // добавление смарт-карты
        void onInsertCard(long hContext, String reader) throws java.lang.Exception;
        // удаление смарт-карты
        void onRemoveCard(long hContext, String reader) throws java.lang.Exception; 
    } 
}
