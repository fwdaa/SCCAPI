package aladdin.asn1;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Выбор из множества объектов
///////////////////////////////////////////////////////////////////////////
public class Choice implements IObjectFactory<IEncodable>
{
    private final ObjectInfo[] info;
    
    // конструктор при раскодировании
    public Choice(ObjectInfo[] info) { this.info = info; } 

    // проверить допустимость типа
    @Override public final boolean isValidTag(Tag tag)
    {
        // для всех возможных альтернатив
		for (ObjectInfo item : info)
		{
            // проверить совпадение типа
            if (item.isValidTag(tag)) return true;
        }
		return false;
    }
    // раскодировать объект
    @Override public final IEncodable decode(IEncodable encodable) throws IOException
    {
        // для всех возможных альтернатив
		for (ObjectInfo item : info)
		{
            // проверить совпадение типа
            if (!item.isValidTag(encodable.tag())) continue;

            // раскодировать объект
            return item.decode(encodable, false);
		}
		// ошибка - некорректный объект
		throw new IOException();
    }
    // проверить корректность объекта
    @Override public final void validate(IEncodable encodable, boolean encode) throws IOException
    {
    	// для всех возможных альтернатив
    	for (ObjectInfo item : info)
        {
            // проверить совпадение типа
            if (!item.isValidTag(encodable.tag())) continue;

            // проверить корректность объекта
            item.validate(encodable, encode); return; 
        }
		// ошибка - некорректный объект
		if (encode) throw new IllegalArgumentException(); else throw new IOException();
    }
}