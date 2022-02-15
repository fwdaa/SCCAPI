package aladdin.iso7816;
import aladdin.asn1.*;
import aladdin.iso7816.ber.*;
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////////
// Реализация криптографических операций
///////////////////////////////////////////////////////////////////////////////
public abstract class SecureClient 
{
    // захэшировать данные
    public abstract byte[] hash(CRT.HT parameters, byte[] data) throws IOException;   
    // вычислить контрольную сумму
    public abstract byte[] checksum(CRT.CCT parameters, byte[][] data) throws IOException;      
    
    // зашифровать данные
    public abstract byte[] encrypt(CRT.CT parameters, byte[] data, int secureType) throws IOException;      
    // расшифровать данные
    public abstract byte[] decrypt(CRT.CT parameters, byte[] data, int secureType) throws IOException;   
    
    // подписать данные
    public abstract byte[] sign(CRT.DST parameters, byte[][] data) throws IOException;      
    // проверить подпись данных
    public abstract void verify(CRT.DST parameters, byte[][] data, byte[] sign) throws IOException;   
    
    // защитить сообщение
    public final byte[] protect(CardEnvironment environment, int secureType, 
        CRT.CT cipherParameters, CRT.CCT macParameters, CRT.DST signParameters, 
        byte cla, byte ins, byte p1, byte p2, byte[] data, int ne) throws IOException
    {
        // получить используемую схему кодирования
        TagScheme tagScheme = environment.tagScheme(); 
        
        // создать список объектов
        List<DataObject> objs = new ArrayList<DataObject>(); 
        
        // проверить использование параметров
        if ((cipherParameters.usageQualifier() & 0x10) == 0) cipherParameters = null; 
        if ((   macParameters.usageQualifier() & 0x10) == 0)    macParameters = null; 
        if ((  signParameters.usageQualifier() & 0x10) == 0)   signParameters = null; 
        
        // признак наличия контроля целостности
        boolean authenticated = (macParameters != null || signParameters != null); 
            
        // при наличии контроля целостности
        byte[] header = null; if (authenticated)
        {
            // при включении заголовка в контроль целостности 
            if ((cla & 0xEC) == 0x0C) header = new byte[] { cla, ins, p1, p2 };
            
            // при включении заголовка в контроль целостности
            else if ((secureType & SecureType.SECURE_HEADER) == SecureType.SECURE_HEADER)
            {
                // command header (CLA INS P1 P2)
                Tag tag = Tag.context(0x09, PC.PRIMITIVE); 
                    
                // закодировать заголовок
                objs.add(new DataObject(Authority.ISO7816, tag, new byte[] { cla, ins, p1, p2 })); 
            }
        }
        // при отсутствии шифрования 
        if (cipherParameters == null)
        {
            // в зависимости от кода команды
            if ((ins & INS.BERTLV) == 0 && (secureType & SecureType.BERTLV) == 0)
            {
                // plain value not encoded in BER-TLV
                Tag tag = Tag.context(authenticated ? 0x01 : 0x00, PC.PRIMITIVE); 

                // закодировать данные
                objs.add(new DataObject(Authority.ISO7816, tag, data)); 
            }
            else if ((secureType & SecureType.BERTLV_SM) != SecureType.BERTLV_SM)
            {
                // plain value encoded in BER-TLV, but not including SM DOs
                Tag tag = Tag.context(authenticated ? 0x13 : 0x12, PC.CONSTRUCTED); 

                // закодировать данные
                objs.add(new DataObjectTemplate(Authority.ISO7816, tag, tagScheme, data)); 
            }
            else {
                // plain value encoded in BER-TLV and including SM DOs
                Tag tag = Tag.context(authenticated ? 0x11 : 0x10, PC.CONSTRUCTED); 

                // закодировать данные
                objs.add(new DataObjectTemplate(Authority.ISO7816, tag, tagScheme, data)); 
            }
        }
        else {
            // в зависимости от кода команды
            if ((ins & INS.BERTLV) == 0 && (secureType & SecureType.BERTLV) == 0)
            {
                // зашифровать данные
                byte[] cryptogram = encrypt(cipherParameters, data, SecureType.NONE); 
                    
                // padding-content indicator byte followed by cryptogram
                Tag tag = Tag.context(authenticated ? 0x07 : 0x06, PC.PRIMITIVE); 
                    
                // закодировать зашифрованные данные
                objs.add(new DataObject(Authority.ISO7816, tag, cryptogram));
            }
            else if ((secureType & SecureType.BERTLV_SM) != SecureType.BERTLV_SM)
            {
                // зашифровать данные
                byte[] cryptogram = encrypt(cipherParameters, data, SecureType.BERTLV); 
                    
                // cryptogram (plain value encoded in BER-TLV, but not including SM DOs)
                Tag tag = Tag.context(authenticated ? 0x05 : 0x04, PC.PRIMITIVE); 
                    
                // закодировать зашифрованные данные
                objs.add(new DataObject(Authority.ISO7816, tag, cryptogram));
            }
            else {
                // зашифровать данные
                byte[] cryptogram = encrypt(cipherParameters, data, SecureType.BERTLV_SM); 
                    
                // сryptogram (plain value encoded in BER-TLV and including SM DOs
                Tag tag = Tag.context(authenticated ? 0x03 : 0x02, PC.PRIMITIVE); 
                    
                // закодировать зашифрованные данные
                objs.add(new DataObject(Authority.ISO7816, tag, cryptogram));
            }
        }
        // при наличии контроля целостности
        if (authenticated && ne != 0) { byte[] le = new byte[0]; 
            
            // признак контроля целостности
            boolean check = (secureType & SecureType.SECURE_HEADER) == SecureType.SECURE_HEADER; 
        
            // оne or two bytes encoding Le in the unsecured C-RP
            Tag tag = Tag.context(check ? 0x17 : 0x16, PC.PRIMITIVE); 
                    
            // при использовании коротких размеров
            if (data.length <= 255 && ne <= 255)
            {
                // закодировать размер
                le = new byte[] { (byte)(ne & 0xFF) }; 
                        
                // закодировать размер
                objs.add(new DataObject(Authority.ISO7816, tag, le)); 
            }
            else {
                // получить возможности смарт-карты
                CardCapabilities cardCapabilities = environment.cardCapabilities(); 
        
                // указать требуемый размер данных
                if (!cardCapabilities.supportExtended())
                {
                    // закодировать размер
                    if (ne < 256) le = new byte[] { (byte)(ne & 0xFF) }; 
                }
                else {
                    // закодировать размер
                    if (ne < 65536) le = new byte[] { (byte)((ne >>> 8) & 0xFF), (byte)(ne & 0xFF) }; 
                }
            }
            // добавить объект в список
            objs.add(new DataObject(Authority.ISO7816, tag, le)); 
        }
        // закодировать объекты
        byte[] encoded = DataObject.encode(tagScheme, objs);
                
        // при наличии контроля целостности
        if (macParameters != null)
        {
            // сryptographic checksum
            Tag tagChecksum = Tag.context(0x0E, PC.PRIMITIVE); if (header != null)
            {
                // вычислить имитовставку
                byte[] checksum = checksum(macParameters, new byte[][] { header, encoded }); 

                // закодировать контрольную сумму
                objs.add(new DataObject(Authority.ISO7816, tagChecksum, checksum)); 
            }
            else {
                // вычислить имитовставку
                byte[] checksum = checksum(macParameters, new byte[][] { encoded }); 

                // закодировать контрольную сумму
                objs.add(new DataObject(Authority.ISO7816, tagChecksum, checksum)); 
            }
        }
        // при наличии подписи
        if (signParameters != null)
        {
            // digital signature
            Tag tagSignature = Tag.context(0x1E, PC.PRIMITIVE); if (header != null)
            {
                // вычислить подпись
                byte[] signature = sign(signParameters, new byte[][] { header, encoded }); 

                // закодировать подпись
                objs.add(new DataObject(Authority.ISO7816, tagSignature, signature)); 
            }
            else {
                // вычислить подпись
                byte[] signature = sign(signParameters, new byte[][] { encoded }); 

                // закодировать подпись
                objs.add(new DataObject(Authority.ISO7816, tagSignature, signature)); 
            }
        }
        // закодировать объекты
        return DataObject.encode(tagScheme, objs);
    }
    // снять защиту с  сообщения
    public final Response unprotect(CardEnvironment environment, 
        CRT.CT cipherParameters, CRT.CCT macParameters, CRT.DST signParameters, 
        Response response) throws IOException
    {
        // проверить код завершения
        if (Response.error(response)) return response; short sw = response.SW; 
        
        // проверить использование параметров
        if ((cipherParameters.usageQualifier() & 0x20) == 0) cipherParameters = null; 
        if ((   macParameters.usageQualifier() & 0x20) == 0)    macParameters = null; 
        if ((  signParameters.usageQualifier() & 0x20) == 0)   signParameters = null; 
        
        // получить используемую схему кодирования
        TagScheme tagScheme = environment.tagScheme(); 
        
        // раскодировать объекты
        DataObject[] objects = environment.dataCoding().decode(response.data, true); 
        
        // указать начальные условия
        List<byte[]> encodeds = new ArrayList<byte[]>(); 
        
        // для всех объектов
        for (int i = 0; i < objects.length; i++)
        {
            // выделить буфер для объектов
            List<DataObject> checkObjects = new ArrayList<DataObject>(); 
                    
            // для всех объектов
            for (int j = i; j < objects.length; j++)
            {
                // проверить контроль объекта
                if (!objects[j].tag().tagClass().equals(TagClass.CONTEXT)) 
                {
                    // добавить объект в список
                    checkObjects.add(objects[j]); continue; 
                }
                // проверить контроль объекта
                else if ((objects[j].tag().tagValue() & 0x1) != 0) 
                {
                    // добавить объект в список
                    checkObjects.add(objects[j]); continue; 
                }
                break; 
            }
            // проверить наличие объектов
            if (checkObjects.isEmpty()) continue; i += checkObjects.size(); 
                
            // закодировать объекты
            encodeds.add(DataObject.encode(tagScheme, checkObjects)); 
        }
        // при наличии контроля целостности
        if (macParameters != null) { byte[] checksum = null; 
        
            // сryptographic checksum
            Tag tagChecksum = Tag.context(0x0E, PC.PRIMITIVE); 
            
            // для всех объектов
            for (int i = objects.length; i > 0; i--)
            {
                // проверить наличие контрольной суммы
                if (objects[i - 1].tag().equals(tagChecksum))
                {
                    // извлечь контрольную сумму
                    checksum = objects[i - 1].content(); break; 
                }
            }
            // проверить наличие контрольной суммы
            if (checksum == null) return new Response((short)0x6987); 
        
            // вычислить контрольную сумму
            byte[] check = checksum(macParameters, encodeds.toArray(new byte[encodeds.size()][])); 
            
            // проверить контрольную сумму
            if (!Arrays.equals(check, check)) return new Response((short)0x6988); 
        }
        // при наличии подписи
        if (signParameters != null) { byte[] signature = null; 
        
            // digital signature
            Tag tagSignature = Tag.context(0x1E, PC.PRIMITIVE); 
            
            // для всех объектов
            for (int i = objects.length; i > 0; i--)
            {
                // проверить наличие подписи
                if (objects[i - 1].tag().equals(tagSignature))
                {
                    // извлечь подпись
                    signature = objects[i - 1].content(); break; 
                }
            }
            // проверить наличие подписи
            if (signature == null) return new Response((short)0x6987); 

            // проверить подпись
            try { verify(signParameters, encodeds.toArray(new byte[encodeds.size()][]), signature); }
            
            // обработать возможную ошибку
            catch (Throwable e) { return new Response((short)0x6988); }
        }
        // создать список объектов
        List<DataObject> result = new ArrayList<DataObject>(); 

        // для всех объектов
        for (DataObject obj : objects)
        {
            // сryptographic checksum
            if (obj.tag().equals(Tag.context(0x0E, PC.PRIMITIVE))) continue; 
                
            // digital signature
            if (obj.tag().equals(Tag.context(0x1E, PC.PRIMITIVE))) continue; 
            
            // processing status (SW1-SW2)
            if (obj.tag().equals(Tag.context(0x19, PC.PRIMITIVE)))
            {
                // проверить наличие статуса
                byte[] content = obj.content(); if (content.length == 0) sw = (short)0x9000; 
                
                // проверить корректность данных
                else if (content.length != 2) return new Response((short)0x6988);
                
                // извлечь статус
                else sw = (short)((content[0] << 8) | content[1]); continue; 
            }
            try { 
                // padding-content indicator byte followed by cryptogram
                if (obj.tag().equals(Tag.context(0x06, PC.PRIMITIVE)))
                {
                    // проверить возможность шифрования
                    if (cipherParameters == null) return new Response((short)0x6988);

                    // plain value not encoded in BER-TLV
                    Tag tag = Tag.context(0x00, PC.PRIMITIVE); 

                    // расшифровать данные
                    byte[] decrypted = decrypt(cipherParameters, obj.content(), SecureType.NONE); 

                    // закодировать данные
                    result.add(new DataObject(Authority.ISO7816, tag, decrypted)); 
                }
                // padding-content indicator byte followed by cryptogram
                else if (obj.tag().equals(Tag.context(0x07, PC.PRIMITIVE)))
                {
                    // проверить возможность шифрования
                    if (cipherParameters == null) return new Response((short)0x6988);

                    // plain value not encoded in BER-TLV
                    Tag tag = Tag.context(0x01, PC.PRIMITIVE); 

                    // расшифровать данные
                    byte[] decrypted = decrypt(cipherParameters, obj.content(), SecureType.NONE); 

                    // закодировать данные
                    result.add(new DataObject(Authority.ISO7816, tag, decrypted)); 
                }
                // cryptogram (plain value encoded in BER-TLV, but not including SM DOs)
                else if (obj.tag().equals(Tag.context(0x04, PC.PRIMITIVE)))
                {
                    // проверить возможность шифрования
                    if (cipherParameters == null) return new Response((short)0x6988);

                    // plain value encoded in BER-TLV, but not including SM DOs
                    Tag tag = Tag.context(0x12, PC.CONSTRUCTED);

                    // расшифровать данные
                    byte[] decrypted = decrypt(cipherParameters, obj.content(), SecureType.BERTLV); 

                    // закодировать данные
                    result.add(new DataObjectTemplate(Authority.ISO7816, tag, tagScheme, decrypted)); 
                }
                // cryptogram (plain value encoded in BER-TLV, but not including SM DOs)
                else if (obj.tag().equals(Tag.context(0x05, PC.PRIMITIVE)))
                {
                    // проверить возможность шифрования
                    if (cipherParameters == null) return new Response((short)0x6988);

                    // plain value encoded in BER-TLV, but not including SM DOs
                    Tag tag = Tag.context(0x13, PC.CONSTRUCTED);

                    // расшифровать данные
                    byte[] decrypted = decrypt(cipherParameters, obj.content(), SecureType.BERTLV); 

                    // закодировать данные
                    result.add(new DataObjectTemplate(Authority.ISO7816, tag, tagScheme, decrypted)); 
                }
                // сryptogram (plain value encoded in BER-TLV and including SM DOs
                else if (obj.tag().equals(Tag.context(0x02, PC.PRIMITIVE)))
                {
                    // проверить возможность шифрования
                    if (cipherParameters == null) return new Response((short)0x6988);

                    // plain value encoded in BER-TLV and including SM DOs
                    Tag tag = Tag.context(0x10, PC.CONSTRUCTED); 

                    // расшифровать данные
                    byte[] decrypted = decrypt(cipherParameters, obj.content(), SecureType.BERTLV_SM); 

                    // закодировать данные
                    result.add(new DataObjectTemplate(Authority.ISO7816, tag, tagScheme, decrypted)); 
                }
                // сryptogram (plain value encoded in BER-TLV and including SM DOs
                else if (obj.tag().equals(Tag.context(0x03, PC.PRIMITIVE)))
                {
                    // проверить возможность шифрования
                    if (cipherParameters == null) return new Response((short)0x6988);

                    // plain value encoded in BER-TLV and including SM DOs
                    Tag tag = Tag.context(0x11, PC.CONSTRUCTED); 

                    // расшифровать данные
                    byte[] decrypted = decrypt(cipherParameters, obj.content(), SecureType.BERTLV_SM); 

                    // закодировать данные
                    result.add(new DataObjectTemplate(Authority.ISO7816, tag, tagScheme, decrypted)); 
                }
                else result.add(obj); 
            }
            // обработать возможное исключение 
            catch (Throwable e) { return new Response((short)0x6988); }
        }
        // закодировать объекты
        return new Response(DataObject.encode(tagScheme, result), sw);
    }
}
