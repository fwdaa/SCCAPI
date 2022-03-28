package aladdin.asn1;
import java.util.*; 
import java.io.*; 
import java.lang.reflect.*; 

///////////////////////////////////////////////////////////////////////////
// Коллекция объектов
///////////////////////////////////////////////////////////////////////////
public class Collection<T extends IEncodable> extends Encodable implements Iterable<T>
{
    private static final long serialVersionUID = -7416893672395847585L;
    
    ///////////////////////////////////////////////////////////////////////
    // Функции коллекции элементов
    ///////////////////////////////////////////////////////////////////////
    public static interface ICastCallback<T extends IEncodable>
    {
    	List<T> invoke(ObjectInfo[] info, List<IEncodable> encodables) throws IOException;
    }
    // коллекция элементов
    private List<T> values; private ObjectInfo[] info;
    
    // конструктор при раскодировании
    public Collection(IEncodable encodable, ObjectInfo[] info, ICastCallback<T> callback) throws IOException
    {
        // создать список объектов
		super(encodable); ArrayList<IEncodable> list = new ArrayList<IEncodable>();

		// проверить корректность способа кодирования
		if (encodable.pc() != PC.CONSTRUCTED) throw new IOException();

        // задать начальные условия
		int length = encodable.content().length; this.info = info;

		// для всех внутренних объектов
		for (int cb = 0; length > 0;)
		{
            // раскодировать внутренний объект
            IEncodable item = Encodable.decode(encodable.content(), cb, length);

            // перейти на следующий объект
            list.add(item); cb += item.encoded().length; length -= item.encoded().length;
        }
		// преобразовать тип объектов
		values = callback.invoke(info, list);
    }
    // конструктор при раскодировании
    @SuppressWarnings({"unchecked"}) 
    public Collection(IEncodable encodable, ObjectInfo info) throws IOException
    {
        // создать список объектов
        super(encodable); values = new ArrayList<T>();

		// проверить корректность способа кодирования
		if (encodable.pc() != PC.CONSTRUCTED) throw new IOException();
	
        // для всех внутренних объектов
		for (int cb = 0, length = encodable.content().length; length > 0;)
		{
            // раскодировать внутренний объект
            IEncodable item = Encodable.decode(encodable.content(), cb, length);

            // проверить совпадение типа
            if (!info.isValidTag(item.tag())) throw new IOException(); 
            
            // раскодировать объект
            values.add((T)info.decode(item, true));
            
            // перейти на следующий объект
            cb += item.encoded().length; length -= item.encoded().length;
        }
		// выделить память для информации о типе
		this.info = new ObjectInfo[values.size()];

		// сохранить информацию о типе
		for (int i = 0; i < this.info.length; i++) this.info[i] = info;
    }
    // конструктор при закодировании
    @SuppressWarnings({"unchecked"}) 
    public Collection(Tag tag, ObjectInfo[] info, IEncodable... values) 
    {
        super(tag, PC.CONSTRUCTED);
	
        // проверить совпадение числа элементов
		if (info.length != values.length) throw new IllegalArgumentException();
	
        // сохранить элементы с информацией о типе
		this.info = info; this.values = new ArrayList<T>();

        // для всех элементов
		for (int i = 0; i < values.length; i++)
		{
            // при наличии элемента
            if (values[i] != null)
            {
                // раскодировать элемент
				try { this.values.add((T)info[i].factory.decode(values[i])); }
				
				// при ошибке выбросить исключение
				catch (IOException e) { throw new IllegalArgumentException(); }
            }
            // при допустимости отсутствия элемента
            else if ((info[i].cast.value() & Cast.O.value()) != 0)
            {
                // установить значение по умолчанию
				this.values.add((T)info[i].value);
            }
            // при ошибке выбросить исключение
            else throw new IllegalArgumentException();
        }
    }
    // конструктор при закодировании
    @SuppressWarnings({"unchecked"}) 
    public Collection(Tag tag, ObjectInfo info, IEncodable... values) 
    {
		super(tag, PC.CONSTRUCTED);
	
        // сохранить переданную информацию
		this.values = new ArrayList<T>(); this.info = new ObjectInfo[values.length];

		// сохранить информацию о типе
		for (int i = 0; i < this.info.length; i++) this.info[i] = info;

		// для всех элементов
		for (int i = 0; i < values.length; i++)
		{
            // проверить наличие элемента
            if (values[i] == null) throw new IllegalArgumentException();

            // раскодировать элемент
            try { this.values.add((T)info.factory.decode(values[i])); }

			// при ошибке выбросить исключение
			catch (IOException e) { throw new IllegalArgumentException(); }
		}
    }
    // сериализация
    @SuppressWarnings({"rawtypes", "unchecked"}) 
    @Override protected void readObject(ObjectInputStream ois) throws IOException 
    {
        // выполнить дополнительные вычисления 
        super.readObject(ois); 
        try {
            // получить конструктор при раскодировании
            Constructor constructor = getClass().getConstructor(IEncodable.class); 
			try {  
				// создать объект 
				Collection instance = (Collection)constructor.newInstance(this); 

				// сохранить внутренние поля объекта
				values = instance.values; info = instance.info; 
			}
			// обработать возможное исключение
			catch (InvocationTargetException e) { throw e.getCause(); }
        }
        // обработать возможное исключение
        catch (IOException e) { throw e; }
        
        // обработать возможное исключение
        catch (Throwable e) { throw new IOException(e); }
    }    
    // содержимое объекта
    @Override protected final byte[] evaluateContent()
    {
		// выделить память для кодирования объектов
		byte[][] encoded = new byte[values.size()][]; int cb = 0;

		// для каждого внутреннего объекта
		for (int i = 0; i < encoded.length; i++)
		{
            // проверить необходимость кодирования
            T value = values.get(i); if (value == null) continue;

            // для необязательного элемента
            if ((info[i].cast.value() & Cast.O.value()) != 0)
            {
                // проверить совпадение с элементом по умолчанию
				if (value.equals(info[i].value)) continue;
            }
            // при явном приведении типа
            if ((info[i].cast.value() & Cast.E.value()) != 0)
            {
                // выполнить явное преобразование
                IEncodable encodable = Encodable.encode(
                    info[i].tag, PC.CONSTRUCTED, value.encoded()
                ); 
                // сохранить закодированное представление
                encoded[i] = encodable.encoded();
            }
            // при неявном переопределении класса и типа
            else if (!info[i].tag.equals(Tag.ANY))
            {
                // выполнить неявное преобразование
                IEncodable encodable = Encodable.encode(
                    info[i].tag, value.pc(), value.content()
                ); 
                // сохранить закодированное представление
                encoded[i] = encodable.encoded();
            }
            // закодировать объект
            else encoded[i] = value.encoded();

            // увеличить общий размер объекта
            cb += encoded[i].length;
        }
        // отсортировать представления
        byte[] content = new byte[cb]; cb = 0; arrangeEncodings(encoded);

        // для каждого внутреннего объекта
        for (int i = 0; i < encoded.length; i++)
        {
            // проверить необходимость кодирования
            if (encoded[i] == null) continue;
			
            // скопировать закодированное представление
            System.arraycopy(encoded[i], 0, content, cb, encoded[i].length);

            // перейти на следующий объект
            cb += encoded[i].length;
        }
        return content;
    }
    // отсортировать представления
    protected void arrangeEncodings(byte[][] encoded) {}

    // перечислитель объектов
    @Override public final Iterator<T> iterator() { return values.iterator(); }
    
    // получить элемент коллекции
    public final T get(int i) { return values.get(i); }

    // установить элемент коллекции
    protected final void put(int i, T value) { values.set(i, value); }
	
    // размер коллекции
    public final int size() { return values.size(); }
}   
 