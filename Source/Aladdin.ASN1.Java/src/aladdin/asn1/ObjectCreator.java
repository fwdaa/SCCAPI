package aladdin.asn1;

///////////////////////////////////////////////////////////////////////////
// Фабрика создания фабрик объектов
///////////////////////////////////////////////////////////////////////////
public final class ObjectCreator
{
    // тип объекта
    private final Class<? extends IEncodable> type;   

    // конструктор
    public ObjectCreator(Class<? extends IEncodable> type) { this.type = type; }
    
    // экземпляр фабрики
    public final IObjectFactory<IEncodable> factory(Object... args)
    {
        // экземпляр фабрики
        try { return new ObjectFactory<IEncodable>(type, args); }
        
        // обработать возможное исключение
        catch (NoSuchMethodException e) { throw new RuntimeException(e); }
    }
}