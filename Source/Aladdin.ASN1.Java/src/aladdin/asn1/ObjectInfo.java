package aladdin.asn1;
import java.io.*;

///////////////////////////////////////////////////////////////////////
// Описание поля в структуре
///////////////////////////////////////////////////////////////////////
public final class ObjectInfo
{
    // фабрика создания объекта
    public final IObjectFactory<? extends IEncodable> factory;    
    
    public final Cast       cast;    // использование типа
    public final Tag        tag;     // тип объекта
    public final IEncodable value;   // значение объекта по умолчанию

    public ObjectInfo(IObjectFactory<? extends IEncodable> factory, Cast cast, Tag tag, IEncodable value)
    {
        // для CHOICE с изменением типа
        if (factory instanceof Choice && !tag.equals(Tag.ANY)) switch (cast)
        {
            // CHOICE не может использоваться IMPLICIT
            case N: cast = Cast.E; break; case O: cast = Cast.EO; break; 
        }
		this.factory = factory;      // фабрика создания объекта
		this.cast    = cast;         // использование типа
		this.tag     = tag;          // тип объекта
		this.value   = value;        // значение объекта по умолчанию
    }
    public ObjectInfo(IObjectFactory<? extends IEncodable> factory, Cast cast, Tag tag)
    {
        // для CHOICE с изменением типа
        if (factory instanceof Choice && !tag.equals(Tag.ANY)) switch (cast)
        {
            // CHOICE не может использоваться IMPLICIT
            case N: cast = Cast.E; break; case O: cast = Cast.EO; break; 
        }
        this.factory = factory;      // фабрика создания объекта
		this.cast    = cast;         // использование типа
		this.tag     = tag;          // тип объекта
		this.value   = null;         // значение объекта по умолчанию
    }
    public ObjectInfo(IObjectFactory<? extends IEncodable> factory, Cast cast)
    {
        this.factory = factory;     // фабрика создания объекта
		this.cast    = cast;        // использование типа
		this.tag     = Tag.ANY;     // тип объекта
		this.value   = null;        // значение объекта по умолчанию
    }
    // признак допустимости типа
    public final boolean isValidTag(Tag tag)
    {
        // проверить допустимость типа
		return (this.tag.equals(Tag.ANY)) ? factory.isValidTag(tag) : (this.tag.equals(tag));
    }
    // раскодировать объект
    public final IEncodable decode(IEncodable encodable, boolean inject) throws IOException
    {
        // при явном приведении типа
		if ((cast.value() & Cast.E.value()) != 0)
    	{
            // извлечь внутренний объект
            IEncodable inner = Encodable.decode(encodable.content());

            // раскодировать внутренний объект
            inner = factory.decode(inner); if (inject) return inner; 
            
            // выполнить явное приведение типа
            return Explicit.encode(encodable.tag(), inner); 
		}
		// раскодировать объект
        else return factory.decode(encodable);
    }
    // проверить корректность объекта
    public final void validate(IEncodable encodable, boolean encode) throws IOException
    {
		// при явном приведении типа
		if ((cast.value() & Cast.E.value()) != 0)
		{
            // извлечь внутренний объект
            IEncodable inner = Encodable.decode(encodable.content()); 

            // проверить корректность объекта
            factory.validate(inner, encode); 
		}
		// проверить корректность объекта
        else factory.validate(encodable, encode);
    }
}