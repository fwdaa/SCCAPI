package aladdin.pcsc;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Считыватель смарт-карт
///////////////////////////////////////////////////////////////////////////
public interface IReader
{
    // имя и состояние считывателя
	String name(); ReaderState getState() throws IOException; 

    // смарт-карта считывателя
    ICard openCard() throws IOException;  
}
