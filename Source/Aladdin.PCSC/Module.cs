namespace Aladdin.PCSC
{
    ///////////////////////////////////////////////////////////////////////////
    // Реализация интерфейса PC/SC
    ///////////////////////////////////////////////////////////////////////////
    public abstract class Module
    {
        // создать контекст
        public abstract ulong EstablishContext(ReaderScope scope);
        // закрыть контекст
        public abstract void ReleaseContext(ulong hContext);

        // перечислить группы считывателей
        public abstract string[] ListReaderGroups(ulong hContext);
        // перечислить считыватели
        public abstract string[] ListReaders(ulong hContext, string[] groups);

	    // состояние считывателя
	    public abstract uint GetState(ulong hContext, string readerName); 

	    // состояние считывателя
	    public ReaderState GetReaderState(ulong hContext, string readerName)
        {
			// получить состояние считывателя и карты
			uint state = GetState(hContext, readerName); 

            // проверить состояние считывателя
            if ((state & API.SCARD_STATE_PRESENT) != 0) return ReaderState.Card; 
	        if ((state & API.SCARD_STATE_EMPTY  ) != 0) return ReaderState.Empty; 
	        if ((state & API.SCARD_STATE_UNKNOWN) != 0) return ReaderState.Unknown; 

	        // вернуть значение по умолчанию
	        return ReaderState.Unavailable;
        }
        // состояние смарт-карты
        public CardState GetCardState(ulong hContext, string readerName)
        {
			// получить состояние считывателя и карты
			uint state = GetState(hContext, readerName); 

	        // проверить состояние считывателя
	        if ((state & API.SCARD_STATE_MUTE     ) != 0) return CardState.Mute; 
	        if ((state & API.SCARD_STATE_EXCLUSIVE) != 0) return CardState.Exclusive; 
	        if ((state & API.SCARD_STATE_INUSE    ) != 0) return CardState.Shared; 
	        if ((state & API.SCARD_STATE_PRESENT  ) != 0) return CardState.Present;

            // вернуть значение по умолчанию
            return CardState.Empty; 
        }
	    // функция прослушивания считывателей
	    public abstract uint ListenReaders(ulong hContext, IReaderHandler readerHandler); 
        // отменить ожидание события смарт-карт
        public abstract void CancelContext(ulong hContext);
 
        // открыть считыватель и смарт-карту
        public abstract ulong Connect(ulong hContext, 
            string reader, OpenMode openMode, ref Protocol protocols
        );
        // заново открыть считыватель и смарт-карту
        public abstract void Reconnect(ulong hCard, 
            CloseMode closeMode, OpenMode openMode, ref Protocol protocols
        );
        // закрыть считыватель и смарт-карту
        public abstract void Disconnect(ulong hCard, CloseMode closeMode);

        // получить состояние считывателя и смарт-карты
        public abstract ReaderStatus GetReaderStatus(ulong hCard); 

        // получить атрибут считывателя
        public abstract byte[] GetReaderAttribute(ulong hCard, uint atrId);
        // установить атрибут считывателя
        public abstract void SetReaderAttribute(ulong hCard, uint atrId, byte[] attr);

        // начать транзакцию со смарт-картой
        public abstract void BeginTransaction(ulong hCard); 
        // завершить транзакцию со смарт-картой
        public abstract void EndTransaction(ulong hCard, CloseMode closeMode); 

        // передать команду считывателю
        public abstract byte[] SendControl(ulong hCard, 
            uint controlCode, byte[] inBuffer, int maxOutBufferSize 
        ); 
        // передать команду смарт-карте
        public abstract byte[] SendCommand(
            ulong hCard, Protocol protocol, byte[] sendBuffer, int maxRecvLength
        );
	    ///////////////////////////////////////////////////////////////////////
	    // Обработчик событий считывателей
	    ///////////////////////////////////////////////////////////////////////
	    public interface IReaderHandler
	    {
            // перечислить считыватели
            string[] ListReaders(ulong hContext); 

		    // добавление считывателя
		    void OnInsertReader(ulong hContext, string reader);
		    // удаление считывателя
            void OnRemoveReader(ulong hContext, string reader); 

		    // добавление смарт-карты
		    void OnInsertCard(ulong hContext, string reader);
		    // удаление смарт-карты
            void OnRemoveCard(ulong hContext, string reader); 
	    } 
    }
}
