package aladdin.asn1;

///////////////////////////////////////////////////////////////////////////
// Фабрика создания объекта для неизвестного типа
///////////////////////////////////////////////////////////////////////////
public final class ImplicitCreator implements IObjectFactory<IEncodable>
{
    // фабрика создания объекта для неизвестного типа
    public static final IObjectFactory<IEncodable> factory = new ImplicitCreator();

    // проверить допустимость типа
    @Override public final boolean isValidTag(Tag tag) { return true; }

	// раскодировать объект
    @Override public final IEncodable decode(IEncodable encodable) { return encodable; }

    // проверить корректность объекта
    @Override public final void validate(IEncodable encodable, boolean encode) {}
}