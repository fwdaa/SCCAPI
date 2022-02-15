package aladdin.io;

///////////////////////////////////////////////////////////////////////////
// Сериализация бинарных данных
///////////////////////////////////////////////////////////////////////////
public class BinarySerializer extends Serializer
{
    // раскодировать объект
    @Override public Object decode(byte[] encoded) { return encoded; }

    // закодировать объект
    @Override public byte[] encode(Object obj)
    {
        // проверить тип объекта
        if (obj instanceof byte[]) return (byte[])obj; 

        // при ошибке выбросить исключение
        throw new UnsupportedOperationException(); 
    }
}
