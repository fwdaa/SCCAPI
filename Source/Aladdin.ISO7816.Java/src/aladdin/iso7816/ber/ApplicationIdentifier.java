package aladdin.iso7816.ber;
import aladdin.iso7816.*;
import aladdin.iso7816.Tag;
import aladdin.asn1.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Идентификатор приложения (0x4F)
///////////////////////////////////////////////////////////////////////////
public class ApplicationIdentifier extends DataObject
{
    // раскодировать идентификатор
    public static ApplicationIdentifier decode(byte[] content) throws IOException
    {
        // проверить корректность размера
        if (content.length == 0) throw new IOException();

        // раскодировать идентификатор
        if (content[0] == 0xE8) return new Standard(content); 
        
        // раскодировать идентификатор
        if (((content[0] >>> 4) & 0x0F) == 0x0A) return new International(content); 
        if (((content[0] >>> 4) & 0x0F) == 0x0D) return new National     (content); 
        if (((content[0] >>> 4) & 0x0F) == 0x0F) return new Proprietary  (content); 
            
        // неизвестный идентификатор
        return new ApplicationIdentifier(content); 
    }
    // конструктор
    public ApplicationIdentifier(byte[] content) throws IOException
    {
        // вызвать базовую функцию
        super(Authority.ISO7816, Tag.APPLICATION_IDENTIFIER, content); 
        
        // проверить корректность размера
        if (content.length == 0) throw new IOException(); 
    }
    // конструктор закодирования
    protected ApplicationIdentifier() 
    { 
        // вызвать базовую функцию
        super(Authority.ISO7816, Tag.APPLICATION_IDENTIFIER); 
    }
    ///////////////////////////////////////////////////////////////////////
    // Незарегистрированный идентификатор
    ///////////////////////////////////////////////////////////////////////
    public static class Proprietary extends ApplicationIdentifier
    {
        // конструктор
        public Proprietary(byte[] content) throws IOException
        {            
            // проверить корректность размера
            super(content); if (content.length > 16) throw new IOException(); 
                
            // проверить корректность
            if ((content[0] & 0xF0) != 0xF0) throw new IOException(); 
        }
    }
    ///////////////////////////////////////////////////////////////////////
    // Идентификатор стандарта
    ///////////////////////////////////////////////////////////////////////
    public static class Standard extends ApplicationIdentifier
    {
        // зарегистрированный идентификатор и дополнительные байты
        public final ObjectIdentifier oid; public final byte[] extension;

        // конструктор закодирования
        public Standard(String oid, byte[] extension)
        {
            // сохранить переданные параметры
            this.oid = new ObjectIdentifier(oid); this.extension = extension; 
                
            // проверить корректность данных
            if (extension.length > 15 - this.oid.content().length) 
            {
                // при ошибке выбросить исключение
                throw new IllegalArgumentException();
            }
        }
        // конструктор раскодирования
        public Standard(byte[] content) throws IOException
        {
            // проверить корректность размера
            super(content); if (content.length > 16) throw new IOException();

            // проверить корректность данных
            if (content[0] != 0xE8) throw new IOException(); 
            
            // раскодированный идентификатор
            ObjectIdentifier decoded = null; int size = content.length - 1; 
            
            // для всевозможных размеров
            for (; size >= 1; size--)
            try {
                // извлечь возможное содержимое OID
                byte[] buffer = new byte[size]; System.arraycopy(content, 1, buffer, 0, size);
                
                // раскодировать идентификатор
                decoded = new ObjectIdentifier(Encodable.encode(
                    aladdin.asn1.Tag.OBJECTIDENTIFIER, PC.PRIMITIVE, buffer
                ));
                break; 
            }
            // проверить наличие идентификатора
            catch (IOException e) {} if (decoded == null) throw new IOException(); 
            
            // сохранить раскодированный идентификатор
            oid = decoded; extension = new byte[content.length - 1 - size];
 
            // сохранить дополнительные байты
            System.arraycopy(content, content.length - extension.length, extension, 0, extension.length); 
        }
        // закодированное представление
        @Override public byte[] content() { byte[] contentOID = oid.content();

            // выделить память для представления
            byte[] encoded = new byte[1 + contentOID.length + extension.length]; 

            // скопировать закодированный идентификатор
            encoded[0] = (byte)0xE8; System.arraycopy(contentOID, 0, encoded, 1, contentOID.length); 

            // скопировать дополнительные байты
            System.arraycopy(extension, 0, encoded, 1 + contentOID.length, extension.length); return encoded; 
        } 
    }
    ///////////////////////////////////////////////////////////////////////
    // Национальный идентификатор
    ///////////////////////////////////////////////////////////////////////
    public static class National extends ApplicationIdentifier
    {
        // описание региона
        public final String region; 

        // идентификатор и дополнительные байты
        public final int rid; public final byte[] pix; 

        // конструктор закодирования
        public National(String region, int rid, byte[] pix)
        {
            // проверить корректность данных
            if (rid >= 1000000 || pix.length > 11) 
            {
                // при ошибке выбросить исключение
                throw new IllegalArgumentException();
            }
            // сохранить переданные параметры
            this.region = region; this.rid = rid; this.pix = pix; 
        }
        // конструктор раскодирования
        public National(byte[] content) throws IOException
        {
            // проверить корректность данных
            if (content.length < 5 || content.length > 16) 
            {
                // при ошибке выбросить исключение
                throw new IOException(); 
            }
            // проверить тип данных
            if (((content[0] >>> 4) & 0x0F) != 0xD || (content[0] & 0xF) > 9) 
            {
                // при ошибке выбросить исключение
                throw new IOException(); 
            }
            // извлечь 8 цифр
            int[] digits = Encoding.decodeDigits(8, content, 1); 
            
            // извлечь код страны
            int code = (content[0] & 0xF) * 100 + digits[0] * 10 + digits[1]; 
            
            // получить описание региона
            region = CountryIndicator.getRegionInfo(code); 
                
            // проверить отсутствие ошибок
            if (region == null) throw new IOException(); int value = 0; 
            
            // вычислить идентификатор
            for (int i = 2; i < 8; i++) value = value * 10 + digits[i]; 
            
            // выделить память для дополнительных байтов
            rid = value; pix = new byte[content.length - 5];
                
            // скопировать дополнительные байты
            System.arraycopy(content, 5, pix, 0, pix.length); 
        }
        // закодированное представление
        @Override public byte[] content()
        {
            // выделить память для закодированного представления
            byte[] encoded = new byte[5 + pix.length]; 

            // получить код региона
            int code = CountryIndicator.getCountryCode(region); 

            // закодировать первый байт
            encoded[0] = (byte)(0xD0 | (code / 100)); code %= 100; 

            // закодировать второй байт
            encoded[1] = (byte)(((code / 10) << 4) | (code % 10)); 
            
            // указать кодируемые цифры
            int[] digits = new int[6]; for (int i = 5, value = rid; i >= 0; i--)
            {
                // указать очередную цифру
                digits[i] = value % 10; value = (value - digits[i]) / 10; 
            }
            // закодировать идентификатор
            Encoding.encodeDigits(digits, encoded, 2);
            
            // скопировать дополнительные байты
            System.arraycopy(pix, 0, encoded, 5, pix.length); return encoded; 
        }
    }
    ///////////////////////////////////////////////////////////////////////
    // Международный идентификатор
    ///////////////////////////////////////////////////////////////////////
    public static class International extends ApplicationIdentifier
    {
        // идентификатор и дополнительные байты
        public final int rid; public final byte[] pix; 

        // конструктор закодирования
        public International(int rid, byte[] pix)
        {
            // проверить корректность данных
            if (rid >= 1000000000 || pix.length > 11) 
            {
                // при ошибке выбросить исключение
                throw new IllegalArgumentException();
            }
            // сохранить переданные параметры
            this.rid = rid; this.pix = pix; 
        }
        // конструктор раскодирования
        public International(byte[] content) throws IOException
        {
            // проверить корректность данных
            if (content.length < 5 || content.length > 16) 
            {
                // при ошибке выбросить исключение
                throw new IOException(); 
            }
            // проверить тип данных
            if ((((content[0] >>> 4) & 0x0F) != 0xA) || (content[0] & 0xF) > 9) 
            {
                // при ошибке выбросить исключение
                throw new IOException(); 
            }
            // извлечь 8 цифр
            int[] digits = Encoding.decodeDigits(8, content, 1); 
            
            // указать первую цифру идентификатора
            int value = (content[0] & 0xF) * 100000000; 
            
            // вычилить идентификатор
            for (int i = 0; i < 8; i++) value = value * 10 + digits[i]; 
            
            // выделить память для дополнительных байтов
            rid = value; pix = new byte[content.length - 5];            

            // скопировать дополнительные байты
            System.arraycopy(content, 5, pix, 0, pix.length); 
        }
        // закодированное представление
        @Override public byte[] content() 
        { 
            // выделить память для закодированного представления
            byte[] encoded = new byte[5 + pix.length]; 

            // закодировать первый байт
            encoded[0] = (byte)(0xA0 | (rid / 100000000)); 
            
            // указать кодируемые цифры
            int[] digits = new int[8]; for (int i = 7, value = rid; i >= 0; i--)
            {
                // указать очередную цифру
                digits[i] = value % 10; value = (value - digits[i]) / 10; 
            }
            // закодировать идентификатор
            Encoding.encodeDigits(digits, encoded, 1);
            
            // скопировать дополнительные байты
            System.arraycopy(pix, 0, encoded, 5, pix.length); return encoded; 
        }
    }
}
