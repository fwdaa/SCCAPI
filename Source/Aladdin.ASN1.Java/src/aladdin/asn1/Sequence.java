package aladdin.asn1;
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Последовательность объектов
///////////////////////////////////////////////////////////////////////////
public class Sequence<T extends IEncodable> extends Collection<T>
{
    private static final long serialVersionUID = -5179913445481073736L;
    
    // проверить допустимость типа
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.SEQUENCE); }
    
    // проверить корректность объекта
    public static void validate(Sequence<? extends IEncodable> encodable, 
        boolean encode, java.lang.Integer min, java.lang.Integer max) throws IOException
    {
		// проверить корректность
		if (encodable != null && encodable.size() < min) 
        {
            // ошибка - некорректный объект
            if (encode) throw new IllegalArgumentException(); else throw new IOException();
        }
		// проверить корректность
		if (encodable != null && encodable.size() > max) 
        {
            // ошибка - некорректный объект
            if (encode) throw new IllegalArgumentException(); else throw new IOException();
        }
    }
    // проверить корректность объекта
    public static void validate(Sequence<? extends IEncodable> encodable, 
        boolean encode, java.lang.Integer min) throws IOException
    {
		// проверить корректность
		if (encodable != null && encodable.size() < min) 
        {
            // ошибка - некорректный объект
            if (encode) throw new IllegalArgumentException(); else throw new IOException();
        }
	}
    // информация об отдельном элементе	
    private static ObjectInfo getInfo(IObjectFactory<? extends IEncodable> factory)
    {
        // атрибуты элемента в последовательности
		return new ObjectInfo(factory, Cast.N, Tag.ANY, null);
    }
    public static class CastCallback<T extends IEncodable> implements ICastCallback<T>
    {
        // приведение типа объектов
        @SuppressWarnings({"unchecked"}) 
        @Override public List<T> invoke(ObjectInfo[] info, List<IEncodable> encodables) throws IOException
        {
            // выделить память для преобразованных объектов
            List<T> values = new ArrayList<T>(); int pos = 0;

			// инициализировать память
			for (int i = 0; i < info.length; i++) values.add(null);

            // для всех раскодированных объектов
            for (int i = 0; i < encodables.size(); i++, pos++)
            {
                // получить значение элемента
                IEncodable encodable = encodables.get(i); 
                
                // для всех элементов
                for (; pos < info.length; pos++)
                {
                    // проверить совпадение типа
                    if (info[pos].isValidTag(encodable.tag())) break;

                    // проверить необязательность элемента
                    if ((info[pos].cast.value() & Cast.O.value()) == 0)
                    {
                        // при ошибке выбросить исключение
                        throw new IOException();
                    }
                    // установить значение элемента по умолчанию
                    values.set(pos, (T)info[pos].value);
                }
                // проверить корректность данных
                if (pos == info.length) return values;

                // раскодировать объект
                values.set(pos, (T)info[pos].decode(encodable, true));
            }
            // для всех непрочитанных элементов
            for (int i = pos; i < info.length; i++)
            {
                // проверить необязательность элемента
                if ((info[i].cast.value() & Cast.O.value()) == 0)
                {
                    // при ошибке выбросить исключение
                    throw new IOException();
                }
                // установить значение элемента по умолчанию
                values.set(i, (T)info[i].value);
            }
            return values;
        }
    }
    // конструктор при раскодировании
    public Sequence(Class<? extends T> type, IEncodable encodable) throws IOException
    {
        this(new ObjectCreator(type).factory(), encodable);
    }
    // конструктор при раскодировании
    public Sequence(IObjectFactory<? extends IEncodable> factory, IEncodable encodable) throws IOException
    {
        super(encodable, getInfo(factory)); 
    }
    // конструктор при раскодировании
    public Sequence(IEncodable encodable) throws IOException
    {
        super(encodable, getInfo(ImplicitCreator.factory)); 
    }
    // конструктор при раскодировании
    protected Sequence(IEncodable encodable, ObjectInfo[] info) throws IOException
    {
        super(encodable, info, new CastCallback<T>()); 
    }
    // конструктор при закодировании
    public Sequence(Class<? extends T> type, IEncodable... values) 
    {
        this(new ObjectCreator(type).factory(), values);
    }
    // конструктор при закодировании
    public Sequence(IObjectFactory<? extends IEncodable> factory, IEncodable... values) 
    {
        super(Tag.SEQUENCE, getInfo(factory), values);
    }
    // конструктор при закодировании
    protected Sequence(ObjectInfo[] info, IEncodable... values) 
    {
        super(Tag.SEQUENCE, info, values);
    }
}