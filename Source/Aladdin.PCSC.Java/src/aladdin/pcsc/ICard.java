package aladdin.pcsc;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Криптографическая смарт-карта
///////////////////////////////////////////////////////////////////////////
public interface ICard
{
    // считыватель и состояние смарт-карты
    IReader reader(); CardState getState() throws IOException;
};
