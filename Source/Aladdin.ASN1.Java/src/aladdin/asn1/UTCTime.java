package aladdin.asn1;
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Дата в диапазоне 1950-2049 
///////////////////////////////////////////////////////////////////////////
public final class UTCTime extends VisibleString
{
    private static final long serialVersionUID = 5467557855714370591L;
    
    // проверить допустимость типа
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.UTCTIME); }
    
    /////////////////////////////////////////////////////////////////////////////
    // Закодировать время
    /////////////////////////////////////////////////////////////////////////////
    private static String encode(Date value)
    {
        // использовать время по Гринвичу
        TimeZone timeZone = TimeZone.getTimeZone("GMT"); 
        
        // получить используемый календарь
        Calendar calendar = Calendar.getInstance(timeZone);  
        
        // получить год даты
		calendar.setTime(value); int year = calendar.get(Calendar.YEAR);

		// проверить корректность даты
        if (year < 1950 || year >= 2050) throw new IllegalArgumentException();
        
		// извлечь сокращенный номер года
        int YY = (year >= 2000) ? year - 2000 : year - 1900;  
        
		// закодировать дату
		return String.format("%1$02d%2$02d%3$02d%4$02d%5$02d%6$02dZ", YY, 
            calendar.get(Calendar.MONTH         ) + 1, 
            calendar.get(Calendar.DAY_OF_MONTH  ), 
            calendar.get(Calendar.HOUR_OF_DAY   ), 
            calendar.get(Calendar.MINUTE        ), 
            calendar.get(Calendar.SECOND        )
        );
    }
    // конструктор при раскодировании
    public UTCTime(IEncodable encodable) throws IOException
    {
        // инициализировать объект
    	super(encodable); init(); 
    }
    // сериализация
    @Override protected void readObject(ObjectInputStream ois) throws IOException 
    {
        // прочитать объект
        super.readObject(ois); init(); 
    }    
    // инициализировать объект
    private void init() throws IOException
    {
        // использовать время по Гринвичу
        String encoded = str(); TimeZone timeZone = TimeZone.getTimeZone("GMT"); 
        
        // получить используемый календарь
        Calendar calendar = Calendar.getInstance(timeZone);  
        
        // извлечь номер года, месяца и дня
		int YY = java.lang.Integer.parseInt(encoded.substring(0, 2));
		int MM = java.lang.Integer.parseInt(encoded.substring(2, 4));
		int DD = java.lang.Integer.parseInt(encoded.substring(4, 6));

		// скорректировать год
		int YYYY = (YY >= 50) ? YY + 1900 : YY + 2000; int ss = 0; int cb = 0;

		// извлечь часы и минуты
		int hh = java.lang.Integer.parseInt(encoded.substring(6,  8));
		int mm = java.lang.Integer.parseInt(encoded.substring(8, 10));

		// при наличии секунд в строке
		if (encoded.charAt(10) != 'Z' && encoded.charAt(10) != '+' && encoded.charAt(10) != '-')
		{
            // извлечь секунды
            ss = java.lang.Integer.parseInt(encoded.substring(10, 12)); cb = 2;
		}
		// установить время календаря
        calendar.set(YYYY, MM - 1, DD, hh, mm, ss);  

		// проверить отсутствие часового пояса
		if (encoded.charAt(10 + cb) == 'Z')
		{
            // проверить корректность данных
            if (encoded.length() != 11 + cb) throw new IOException(); time = calendar.getTime(); return;
        }
		// проверить наличие часового пояса
		if (encoded.charAt(10 + cb) != '+' && encoded.charAt(10 + cb) != '-') throw new IOException();

		// проверить корректность данных
		if (encoded.length() != 15 + cb) throw new IOException();
	
		// извлечь часы и минуты коррекции
		int hhz = java.lang.Integer.parseInt(encoded.substring(10 + cb, 10 + cb + 2));
		int mmz = java.lang.Integer.parseInt(encoded.substring(12 + cb, 12 + cb + 2));

		// учесть направление коррекции
		if (encoded.charAt(10 + cb) == '+') { hhz = -hhz; mmz = -mmz; }

        // скорректировать время 
        calendar.add(Calendar.HOUR, hhz); calendar.add(Calendar.MINUTE, mmz); time = calendar.getTime();    
    }
    // конструктор при закодировании
    public UTCTime(Date time) 
    {
    	super(Tag.UTCTIME, UTCTime.encode(time)); this.time = time; 
    }
    // содержимое объекта
    @Override protected final byte[] derContent() 
    {
		// закодировать содержимое объекта
		try { return UTCTime.encode(time).getBytes("US-ASCII"); } 
        
        // обработать возможное исключение
        catch (UnsupportedEncodingException e) { throw new RuntimeException(e); }
    }
    // закодированное время
    public final Date date() { return time; } private Date time;
}