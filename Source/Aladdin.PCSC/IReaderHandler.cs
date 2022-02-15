namespace Aladdin.PCSC
{
	///////////////////////////////////////////////////////////////////////
	// Обработчик событий считывателей
	///////////////////////////////////////////////////////////////////////
	public interface IReaderHandler
	{
		// добавление считывателя
        void OnInsertReader(Reader reader); 
		// удаление считывателя
        void OnRemoveReader(Reader reader); 

		// добавление смарт-карты
		void OnInsertCard(Reader reader);
		// удаление смарт-карты
        void OnRemoveCard(Reader reader); 
	} 
}
