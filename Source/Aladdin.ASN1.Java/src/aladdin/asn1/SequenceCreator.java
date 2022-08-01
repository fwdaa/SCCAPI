package aladdin.asn1;

///////////////////////////////////////////////////////////////////////////
// Фабрика создания фабрик объектов SEQUENCE
///////////////////////////////////////////////////////////////////////////
public final class SequenceCreator
{
    // тип объекта
    private final Class<? extends IEncodable> type;   

    // конструктор
    public SequenceCreator(Class<? extends IEncodable> type) { this.type = type; }
    
    // экземпляр фабрики
    public final IObjectFactory<IEncodable> factory(Object... args)
    {
        // экземпляр фабрики
        try { return new SequenceFactory<IEncodable>(type, args); }
        
        // обработать возможное исключение
        catch (NoSuchMethodException e) { throw new RuntimeException(e); }
    }
}
