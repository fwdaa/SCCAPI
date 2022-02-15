package aladdin.asn1;
import aladdin.util.*; 
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Множество объектов
///////////////////////////////////////////////////////////////////////////
public class Set<T extends IEncodable> extends Collection<T>
{
    // проверить допустимость типа
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.SET); }
    
    // проверить корректность объекта
    public static void validate(Set<? extends IEncodable> encodable, 
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
    public static void validate(Set<? extends IEncodable> encodable, 
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
        // атрибуты элемента в множестве
		return new ObjectInfo(factory, Cast.N, Tag.ANY, null);
    }
    public static class CastCallback<T extends IEncodable> implements ICastCallback<T>
    {
        // приведение типа объектов
        @SuppressWarnings({"unchecked"}) 
        @Override public List<T> invoke(ObjectInfo[] info, List<IEncodable> encodables) throws IOException
        {
            // выделить память для преобразованных объектов
            List<T> values = new ArrayList<T>();
			
			// инициализировать память
			for (int i = 0; i < info.length; i++) values.add(null);

            // для всех раскодированных объектов
            for (int i = 0; i < encodables.size(); i++)
            {
                // получить значение элемента
                IEncodable encodable = encodables.get(i);
                
                // для всех элементов
                int pos; for (pos = 0; pos < info.length; pos++)
                {
                    // проверить совпадение типа
                    if (info[pos].isValidTag(encodable.tag())) break;
                }
                // проверить корректность данных
                if (pos == info.length) continue;

                // проверить первое появление объекта
                if (values.get(pos) != null) throw new IOException();
			
                // раскодировать объект
                values.set(pos, (T)info[pos].decode(encodable, true));
            }
            // для всех непрочитанных элементов
            for (int i = 0; i < info.length; i++)
            {
                // проверить наличие элемента
                if (values.get(i) != null) continue;

                // проверить допустимость отсутствия элемента
                if ((info[i].cast.value() & Cast.O.value()) == 0)
                {
                     // при ошибке выбросить исключение
                    throw new IOException();
                }
                // установить значение по умолчанию
                values.set(i, (T)info[i].value);
            }
            return values;
        }
    }
    // конструктор при раскодировании
    public Set(Class<? extends T> type, IEncodable encodable) throws IOException
    {
        this(new ObjectCreator(type).factory(), encodable);
    }
    // конструктор при раскодировании
    public Set(IObjectFactory<? extends IEncodable> factory, IEncodable encodable) throws IOException
    {
        super(encodable, getInfo(factory), new CastCallback<T>()); 
    }
    // конструктор при раскодировании
    public Set(IEncodable encodable) throws IOException
    {
        super(encodable, getInfo(ImplicitCreator.factory), new CastCallback<T>()); 
    }
    // конструктор при раскодировании
    protected Set(IEncodable encodable, ObjectInfo[] info) throws IOException
    {
        super(encodable, info, new CastCallback<T>()); 
    }
    // конструктор при закодировании
    public Set(Class<? extends T> type, IEncodable... values) 
    {
        this(new ObjectCreator(type).factory(), values);
    }
    // конструктор при закодировании
    public Set(IObjectFactory<? extends IEncodable> factory, IEncodable... values) 
    {
        super(Tag.SET, getInfo(factory), values);
    }
    // конструктор при закодировании
    protected Set(ObjectInfo[] info, IEncodable... values) 
    {
        super(Tag.SET, info, values);
    }
    // отсортировать представления
    @Override protected final void arrangeEncodings(byte[][] encoded)
    {
        // способ сравнения массивов
        class Comparator implements java.util.Comparator<byte[]>
        {
            // выполнить сравнение массивов
            @Override public int compare(byte[] arr1, byte[] arr2) 
            { 
                // выполнить сравнение массивов
                return Array.compareUnsigned(arr1, arr2); 
            }
        }
        // отсортировать представления
		Arrays.sort(encoded, new Comparator());
    }
}