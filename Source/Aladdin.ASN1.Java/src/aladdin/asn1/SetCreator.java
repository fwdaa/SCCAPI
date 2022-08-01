package aladdin.asn1;

///////////////////////////////////////////////////////////////////////////
// Фабрика создания фабрик объектов SET
///////////////////////////////////////////////////////////////////////////
public final class SetCreator
{
    // тип объекта
    private final Class<? extends IEncodable> type;   

    // конструктор
    public SetCreator(Class<? extends IEncodable> type) { this.type = type; }
    
    // экземпляр фабрики
    public final IObjectFactory<IEncodable> factory(Object... args)
    {
        // экземпляр фабрики
        try { return new SetFactory<IEncodable>(type, args); }
        
        // обработать возможное исключение
        catch (NoSuchMethodException e) { throw new RuntimeException(e); }
    }
}
