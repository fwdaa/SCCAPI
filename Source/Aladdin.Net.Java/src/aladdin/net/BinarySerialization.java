package aladdin.net;

///////////////////////////////////////////////////////////////////////
// Сериализация бинарных данных
///////////////////////////////////////////////////////////////////////
public class BinarySerialization<T> extends Serialization
{
    // создание сериализаций данных
    private final aladdin.io.Serialization serialization; 
        
    // конструктор
    public BinarySerialization(aladdin.io.Serialization serialization)
    {
        // сохранить переданные параметры
        this.serialization = serialization; 
    }
    // создать способ записи/чтения данных
    @Override public Serializer getSerializer(Class<?> type)
    {
        // проверить необходимость данных
        if (type == null) return new BinarySerializer<T>(null); 
        
        // создать способ записи/чтения бинарных данных
        if (type.equals(byte[].class)) return new BinarySerializer<T>(); 
            
        // вернуть способ сериализации
        return new BinarySerializer<T>(serialization.getSerializer(type)); 
    }
}
