package aladdin.asn1;
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Произвольная дата
///////////////////////////////////////////////////////////////////////////
public final class GeneralizedTime extends VisibleString
{
    private static final long serialVersionUID = -633192662888974738L;

    // проверить допустимость типа
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.GENERALIZEDTIME); }
    
    /////////////////////////////////////////////////////////////////////////////
    // Закодировать время
    /////////////////////////////////////////////////////////////////////////////
    private static String encode(Date value)
    {
        // получить используемый календарь
        Calendar calendar = Calendar.getInstance(); calendar.setTime(value); 
        
        // закодировать дату
		return String.format("%1$04d%2$02d%3$02d%4$02d%5$02d%6$02dZ", 
            calendar.get(Calendar.YEAR          ), 
            calendar.get(Calendar.MONTH         ) + 1, 
            calendar.get(Calendar.DAY_OF_MONTH  ), 
            calendar.get(Calendar.HOUR_OF_DAY   ), 
            calendar.get(Calendar.MINUTE        ), 
            calendar.get(Calendar.SECOND        )
        );
    }
    private static String encode(Date value, String frac)
    {
        // закодировать дату
		String encoded = GeneralizedTime.encode(value);

		// добавить дробную часть секунд
		return (frac.length() != 0) ? String.format("%1$s.%2$s", encoded, frac) : encoded;
    }
    // конструктор при раскодировании
    public GeneralizedTime(IEncodable encodable) throws IOException
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
        String encoded = str(); String frac = "";

        // использовать время по Гринвичу
        TimeZone timeZone = TimeZone.getDefault(); 
        
        // установить используемый календарь
        Calendar calendar = Calendar.getInstance(timeZone);   
       
		// извлечь номер года, месяца, дня и часы
		int YYYY = java.lang.Integer.parseInt(encoded.substring(0,  4));
		int MM   = java.lang.Integer.parseInt(encoded.substring(4,  6));
		int DD   = java.lang.Integer.parseInt(encoded.substring(6,  8));
		int hh   = java.lang.Integer.parseInt(encoded.substring(8, 10));

         // установить время календаря
        calendar.set(YYYY, MM - 1, DD, hh, 0, 0); int cb = 0; 
       
        // проверить необходимость дальнейших действий
		if (encoded.length() == 10) { time = calendar.getTime(); this.fractional = frac; return; } 

		// наличие дробной части в часах не поддерживается 
		if (encoded.charAt(10) == '.' || encoded.charAt(10) == ',') throw new IOException();

		// при наличии минут
		if (encoded.charAt(10) != 'Z' && encoded.charAt(10) != '+' && encoded.charAt(10) != '-')
		{
            // прочитать минуты
            int mm = java.lang.Integer.parseInt(encoded.substring(10, 12)); 
            
            // добавить минуты к дате
            calendar.add(Calendar.MINUTE, mm); cb = 2;

            // проверить необходимость дальнейших действий
            if (encoded.length() == 12) { time = calendar.getTime(); this.fractional = frac; return; } 

            // наличие дробной части в минутах не поддерживается 
            if (encoded.charAt(12) == '.' || encoded.charAt(12) == ',') throw new IOException();

            // при наличии секунд
            if (encoded.charAt(12) != 'Z' && encoded.charAt(12) != '+' && encoded.charAt(12) != '-')
            {
				// прочитать секунды
                int ss = java.lang.Integer.parseInt(encoded.substring(12, 14)); 
		
                // добавить секунды
                calendar.add(Calendar.SECOND, ss); cb = 4;

				// проверить необходимость дальнейших действий
				if (encoded.length() == 14) { time = calendar.getTime(); this.fractional = frac; return; }  
                
				// при наличии дробной части в секундах
				if (encoded.charAt(14) == '.' || encoded.charAt(14) == ',')
				{
                    // проверить корректность данных
                    if (!Character.isDigit(encoded.charAt(15))) throw new IOException();

                    // определить число цифр в дробной части
                    int i = 1; while (15 + i < encoded.length() && Character.isDigit(encoded.charAt(15 + i))) i++;

                    // проигнорировать незначимые нули
                    cb = 5 + i; while (encoded.charAt(15 + i) == '0') i--; if (i > 0)
                    {
                        // сохранить дробную часть
                        frac = "." + encoded.substring(15, 15 + i);
                        
                        // определить миллисекунды
                        int ms = (int)((double)1000 * Double.parseDouble(frac)); 

						// добавить миллисекунды
                        calendar.add(Calendar.MILLISECOND, ms); 
                    }
				}
            }
        }
		// проверить необходимость дальнейших действий
		if (encoded.length() == 10 + cb) { time = calendar.getTime(); this.fractional = frac; return; } 

        // проверить указание времени по Гринвичу
		if (encoded.charAt(10 + cb) == 'Z')
		{
            // проверить корректность данных
            if (encoded.length() != 11 + cb) throw new IOException();

            // указать время по Гринвичу 
            calendar.setTimeZone(TimeZone.getTimeZone("GMT")); 
            
            // сохранить время по Гринвичу
            time = calendar.getTime(); this.fractional = frac; return;
		}
		// проверить наличие часового пояса
		if (encoded.charAt(10 + cb) != '+' && encoded.charAt(10 + cb) != '-') throw new IOException();

		// проверить размер строки
		if (encoded.length() != 15 + cb) throw new IOException();

		// извлечь часы и минуты коррекции
		int hhz = java.lang.Integer.parseInt(encoded.substring(11 + cb, 11 + cb + 2));
		int mmz = java.lang.Integer.parseInt(encoded.substring(13 + cb, 13 + cb + 2));

		// учесть направление коррекции
		if (encoded.charAt(10 + cb) == '+') { hhz = -hhz; mmz = -mmz; }
        
        // скорректировать время 
        calendar.add(Calendar.HOUR, hhz); calendar.add(Calendar.MINUTE, mmz); 
        
        // сохранить время
        time = calendar.getTime(); this.fractional = frac;    
    }
    // конструктор при закодировании
    public GeneralizedTime(Date time) 
    {
		super(Tag.GENERALIZEDTIME, GeneralizedTime.encode(time));

        // сохранить время
		this.time = time; fractional = "";
    }
    // содержимое объекта
    @Override protected final byte[] derContent()
    {
    	// закодировать содержимое объекта
        try { return GeneralizedTime.encode(time, fractional).getBytes("US-ASCII"); }
        
        // обработать возможную ошибку
        catch (UnsupportedEncodingException e) { throw new RuntimeException(e); }
    }
    // закодированное время
    public final Date date() { return time; }

    // время и дробная часть секунд
    private Date time; private String fractional;
}