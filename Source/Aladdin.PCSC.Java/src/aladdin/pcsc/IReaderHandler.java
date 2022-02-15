package aladdin.pcsc;

///////////////////////////////////////////////////////////////////////
// Обработчик событий считывателей
///////////////////////////////////////////////////////////////////////
public interface IReaderHandler
{
	// добавление считывателя
	void onInsertReader(Reader reader) throws Exception;
	// удаление считывателя
    void onRemoveReader(Reader reader) throws Exception;

	// добавление смарт-карты
	void onInsertCard(Reader reader) throws Exception;
	// удаление смарт-карты
    void onRemoveCard(Reader reader) throws Exception;
} 
