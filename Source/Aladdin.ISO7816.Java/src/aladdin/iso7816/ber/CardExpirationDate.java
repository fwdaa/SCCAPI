package aladdin.iso7816.ber;
import aladdin.iso7816.*; 
import java.text.*; 
import java.util.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Дата истечения срока действия карты (0x59)
///////////////////////////////////////////////////////////////////////////
public class CardExpirationDate extends DataObject
{
    // дата истечения срока действия карты
    public final Date date; 

    // конструктор
    public CardExpirationDate(byte[] content) throws IOException
    {    
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.CARD_EXPIRATION_DATE, content); 
        
        // раскодировать цифры
        int[] digits = Encoding.decodeDigits(4, content, 0);
    
        // извлечь год и месяц
        int yy = digits[0] * 10 + digits[1]; int MM = digits[2] * 10 + digits[3];

        // указать формат даты
        DateFormat dateFormat = new SimpleDateFormat("yyMM"); 

        // раскодировать дату
        try { date = dateFormat.parse(String.format("%1$02d%2$02d", yy, MM)); }
        
        // обработать неожидаемое исключение
        catch (ParseException e) { throw new IOException(e); }
    } 
}
