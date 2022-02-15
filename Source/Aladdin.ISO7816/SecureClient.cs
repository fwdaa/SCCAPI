using System; 
using System.Collections.Generic;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////////
    // Реализация криптографических операций
    ///////////////////////////////////////////////////////////////////////////////
    public abstract class SecureClient 
    {
        // захэшировать данные
        public abstract byte[] Hash(BER.CRT.HT parameters, byte[] data);
        // вычислить контрольную сумму
        public abstract byte[] Checksum(BER.CRT.CCT parameters, byte[][] data); 
    
        // зашифровать данные
        public abstract byte[] Encrypt(BER.CRT.CT parameters, byte[] data, SecureType secureType);
        // расшифровать данные
        public abstract byte[] Decrypt(BER.CRT.CT parameters, byte[] data, SecureType secureType);
    
        // подписать данные
        public abstract byte[] Sign(BER.CRT.DST parameters, byte[][] data);
        // проверить подпись данных
        public abstract void Verify(BER.CRT.DST parameters, byte[][] data, byte[] sign);

        // защитить сообщение
        public byte[] Protect(CardEnvironment environment, SecureType secureType, 
            BER.CRT.CT cipherParameters, BER.CRT.CCT macParameters, BER.CRT.DST signParameters, 
            byte cla, byte ins, byte p1, byte p2, byte[] data, int ne) 
        {
            // создать список объектов
            List<DataObject> objs = new List<DataObject>(); TagScheme tagScheme = environment.TagScheme;
        
            // проверить использование параметров
            if ((cipherParameters.UsageQualifier & 0x10) == 0) cipherParameters = null; 
            if ((   macParameters.UsageQualifier & 0x10) == 0)    macParameters = null; 
            if ((  signParameters.UsageQualifier & 0x10) == 0)   signParameters = null; 
            
            // признак наличия контроля целостности
            bool authenticated = (macParameters != null || signParameters != null); 
            
            // при наличии контроля целостности
            byte[] header = null; if (authenticated)
            {
                // при включении заголовка в контроль целостности 
                if ((cla & 0xEC) == 0x0C) header = new byte[] { cla, ins, p1, p2 };
            
                // при включении заголовка в контроль целостности
                else if ((secureType & SecureType.SecureHeader) == SecureType.SecureHeader)
                {
                    // command header (CLA INS P1 P2)
                    Tag tag = Tag.Context(0x09, ASN1.PC.Primitive); 
                    
                    // закодировать заголовок
                    objs.Add(new DataObject(Authority.ISO7816, tag, new byte[] { cla, ins, p1, p2 })); 
                }
            }
            // при отсутствии шифрования 
            if (cipherParameters == null)
            {
                // в зависимости от кода команды
                if ((ins & INS.BERTLV) == 0 && (secureType & SecureType.BERTLV) == 0)
                {
                    // plain value not encoded in BER-TLV
                    Tag tag = Tag.Context(authenticated ? 0x01 : 0x00, ASN1.PC.Primitive); 

                    // закодировать данные
                    objs.Add(new DataObject(Authority.ISO7816, tag, data)); 
                }
                else if ((secureType & SecureType.BERTLVSM) != SecureType.BERTLVSM)
                {
                    // plain value encoded in BER-TLV, but not including SM DOs
                    Tag tag = Tag.Context(authenticated ? 0x13 : 0x12, ASN1.PC.Constructed); 

                    // закодировать данные
                    objs.Add(new DataObjectTemplate(Authority.ISO7816, tag, tagScheme, data)); 
                }
                else {
                    // plain value encoded in BER-TLV and including SM DOs
                    Tag tag = Tag.Context(authenticated ? 0x11 : 0x10, ASN1.PC.Constructed); 

                    // закодировать данные
                    objs.Add(new DataObjectTemplate(Authority.ISO7816, tag, tagScheme, data)); 
                }
            }
            else {
                // в зависимости от кода команды
                if ((ins & INS.BERTLV) == 0 && (secureType & SecureType.BERTLV) == 0)
                {
                    // зашифровать данные
                    byte[] cryptogram = Encrypt(cipherParameters, data, SecureType.None); 
                    
                    // padding-content indicator byte followed by cryptogram
                    Tag tag = Tag.Context(authenticated ? 0x07 : 0x06, ASN1.PC.Primitive); 
                    
                    // закодировать зашифрованные данные
                    objs.Add(new DataObject(Authority.ISO7816, tag, cryptogram));
                }
                else if ((secureType & SecureType.BERTLVSM) != SecureType.BERTLVSM)
                {
                    // зашифровать данные
                    byte[] cryptogram = Encrypt(cipherParameters, data, SecureType.BERTLV); 
                    
                    // cryptogram (plain value encoded in BER-TLV, but not including SM DOs)
                    Tag tag = Tag.Context(authenticated ? 0x05 : 0x04, ASN1.PC.Primitive); 
                    
                    // закодировать зашифрованные данные
                    objs.Add(new DataObject(Authority.ISO7816, tag, cryptogram));
                }
                else {
                    // зашифровать данные
                    byte[] cryptogram = Encrypt(cipherParameters, data, SecureType.BERTLVSM); 
                    
                    // сryptogram (plain value encoded in BER-TLV and including SM DOs
                    Tag tag = Tag.Context(authenticated ? 0x03 : 0x02, ASN1.PC.Primitive); 
                    
                    // закодировать зашифрованные данные
                    objs.Add(new DataObject(Authority.ISO7816, tag, cryptogram));
                }
            }
            // при наличии контроля целостности
            if (authenticated && ne != 0) { byte[] le = new byte[0]; 
        
                // признак контроля целостности
                bool check = (secureType & SecureType.SecureHeader) == SecureType.SecureHeader; 

                // оne or two bytes encoding Le in the unsecured C-RP
                Tag tag = Tag.Context(check ? 0x17 : 0x16, ASN1.PC.Primitive); 
                
                // при использовании коротких размеров
                if (data.Length <= 255 && ne <= 255)
                {
                    // закодировать размер
                    le = new byte[] { (byte)(ne & 0xFF) }; 
                    
                    // закодировать размер
                    objs.Add(new DataObject(Authority.ISO7816, tag, le)); 
                }
                else {
                    // получить возможности смарт-карты
                    BER.CardCapabilities cardCapabilities = environment.CardCapabilities; 
    
                    // указать требуемый размер данных
                    if (!cardCapabilities.SupportExtended)
                    {
                        // закодировать размер
                        if (ne < 256) le = new byte[] { (byte)(ne & 0xFF) }; 
                    }
                    else {
                        // закодировать размер
                        if (ne < 65536) le = new byte[] { (byte)(ne >> 8), (byte)(ne & 0xFF) }; 
                    }
                }
                // добавить объект в список
                objs.Add(new DataObject(Authority.ISO7816, tag, le)); 
            }
            // закодировать объекты
            byte[] encoded = DataObject.Encode(tagScheme, objs);
            
            if (macParameters != null)
            {
                // сryptographic checksum
                Tag tagChecksum = Tag.Context(0x0E, ASN1.PC.Primitive); if (header != null)
                {
                    // вычислить имитовставку
                    byte[] checksum = Checksum(macParameters, new byte[][] { header, encoded }); 

                    // закодировать контрольную сумму
                    objs.Add(new DataObject(Authority.ISO7816, tagChecksum, checksum)); 
                }
                else {
                    // вычислить имитовставку
                    byte[] checksum = Checksum(macParameters, new byte[][] { encoded }); 

                    // закодировать контрольную сумму
                    objs.Add(new DataObject(Authority.ISO7816, tagChecksum, checksum)); 
                }
            }
            // при наличии подписи
            if (signParameters != null)
            {
                // digital signature
                Tag tagSignature = Tag.Context(0x1E, ASN1.PC.Primitive); if (header != null)
                {
                    // вычислить подпись
                    byte[] signature = Sign(signParameters, new byte[][] { header, encoded }); 

                    // закодировать подпись
                    objs.Add(new DataObject(Authority.ISO7816, tagSignature, signature)); 
                }
                else {
                    // вычислить подпись
                    byte[] signature = Sign(signParameters, new byte[][] { encoded }); 

                    // закодировать подпись
                    objs.Add(new DataObject(Authority.ISO7816, tagSignature, signature)); 
                }
            }
            // закодировать объекты
            return DataObject.Encode(tagScheme, objs);
        }
        // снять защиту с сообщения
        public Response Unprotect(CardEnvironment environment, 
            BER.CRT.CT cipherParameters, BER.CRT.CCT macParameters, BER.CRT.DST signParameters, 
            Response response)
        {
            // проверить код завершения
            if (Response.Error(response)) return response; ushort sw = response.SW; 
        
            // проверить использование параметров
            if ((cipherParameters.UsageQualifier & 0x20) == 0) cipherParameters = null; 
            if ((   macParameters.UsageQualifier & 0x20) == 0)    macParameters = null; 
            if ((  signParameters.UsageQualifier & 0x20) == 0)   signParameters = null; 
        
            // получить используемую схему кодирования
            TagScheme tagScheme = environment.TagScheme; 
        
            // раскодировать объекты
            DataObject[] objects = environment.DataCoding.Decode(response.Data, true); 
        
            // указать начальные условия
            List<Byte[]> encodeds = new List<Byte[]>(); 
        
            // для всех объектов
            for (int i = 0; i < objects.Length; i++)
            {
                // выделить буфер для объектов
                List<DataObject> checkObjects = new List<DataObject>(); 
                    
                // для всех объектов
                for (int j = i; j < objects.Length; j++)
                {
                    // проверить контроль объекта
                    if (objects[j].Tag.Class != ASN1.TagClass.Context) 
                    {
                        // добавить объект в список
                        checkObjects.Add(objects[j]); continue; 
                    }
                    // проверить контроль объекта
                    else if ((objects[j].Tag.Value & 0x1) != 0) 
                    {
                        // добавить объект в список
                        checkObjects.Add(objects[j]); continue; 
                    }
                    break; 
                }
                // проверить наличие объектов
                if (checkObjects.Count == 0) continue; i += checkObjects.Count; 
                
                // закодировать объекты
                encodeds.Add(DataObject.Encode(tagScheme, checkObjects)); 
            }
            // при наличии контроля целостности
            if (macParameters != null) { byte[] checksum = null; 
        
                // сryptographic checksum
                Tag tagChecksum = Tag.Context(0x0E, ASN1.PC.Primitive); 
            
                // для всех объектов
                for (int i = objects.Length; i > 0; i--)
                {
                    // проверить наличие контрольной суммы
                    if (objects[i - 1].Tag == tagChecksum)
                    {
                        // извлечь контрольную сумму
                        checksum = objects[i - 1].Content; break; 
                    }
                }
                // проверить наличие контрольной суммы
                if (checksum == null) return new Response(0x6987); 
        
                // вычислить контрольную сумму
                byte[] check = Checksum(macParameters, encodeds.ToArray()); 
            
                // проверить контрольную сумму
                if (!Arrays.Equals(check, check)) return new Response(0x6988); 
            }
            // при наличии подписи
            if (signParameters != null) { byte[] signature = null; 
        
                // digital signature
                Tag tagSignature = Tag.Context(0x1E, ASN1.PC.Primitive); 
            
                // для всех объектов
                for (int i = objects.Length; i > 0; i--)
                {
                    // проверить наличие подписи
                    if (objects[i - 1].Tag == tagSignature)
                    {
                        // извлечь подпись
                        signature = objects[i - 1].Content; break; 
                    }
                }
                // проверить наличие подписи
                if (signature == null) return new Response(0x6987); 

                // проверить подпись
                try { Verify(signParameters, encodeds.ToArray(), signature); }
            
                // обработать возможную ошибку
                catch { return new Response(0x6988); }
            }
            // создать список объектов
            List<DataObject> result = new List<DataObject>(); 

            // для всех объектов
            foreach (DataObject obj in objects)
            {
                // сryptographic checksum
                if (obj.Tag == Tag.Context(0x0E, ASN1.PC.Primitive)) continue; 
                
                // digital signature
                if (obj.Tag == Tag.Context(0x1E, ASN1.PC.Primitive)) continue; 
            
                // processing status (SW1-SW2)
                if (obj.Tag == Tag.Context(0x19, ASN1.PC.Primitive))
                {
                    // проверить наличие статуса
                    byte[] content = obj.Content; if (content.Length == 0) sw = 0x9000; 
                
                    // проверить корректность данных
                    else if (content.Length != 2) return new Response(0x6988);
                
                    // извлечь статус
                    else sw = (ushort)((content[0] << 8) | content[1]); continue; 
                }
                try { 
                    // padding-content indicator byte followed by cryptogram
                    if (obj.Tag == Tag.Context(0x06, ASN1.PC.Primitive))
                    {
                        // проверить возможность шифрования
                        if (cipherParameters == null) return new Response(0x6988);

                        // plain value not encoded in BER-TLV
                        Tag tag = Tag.Context(0x00, ASN1.PC.Primitive); 

                        // расшифровать данные
                        byte[] decrypted = Decrypt(cipherParameters, obj.Content, SecureType.None); 

                        // закодировать данные
                        result.Add(new DataObject(Authority.ISO7816, tag, decrypted)); 
                    }
                    // padding-content indicator byte followed by cryptogram
                    else if (obj.Tag == Tag.Context(0x07, ASN1.PC.Primitive))
                    {
                        // проверить возможность шифрования
                        if (cipherParameters == null) return new Response(0x6988);

                        // plain value not encoded in BER-TLV
                        Tag tag = Tag.Context(0x01, ASN1.PC.Primitive); 

                        // расшифровать данные
                        byte[] decrypted = Decrypt(cipherParameters, obj.Content, SecureType.None); 

                        // закодировать данные
                        result.Add(new DataObject(Authority.ISO7816, tag, decrypted)); 
                    }
                    // cryptogram (plain value encoded in BER-TLV, but not including SM DOs)
                    else if (obj.Tag == Tag.Context(0x04, ASN1.PC.Primitive))
                    {
                        // проверить возможность шифрования
                        if (cipherParameters == null) return new Response(0x6988);

                        // plain value encoded in BER-TLV, but not including SM DOs
                        Tag tag = Tag.Context(0x12, ASN1.PC.Constructed);

                        // расшифровать данные
                        byte[] decrypted = Decrypt(cipherParameters, obj.Content, SecureType.BERTLV); 

                        // закодировать данные
                        result.Add(new DataObjectTemplate(Authority.ISO7816, tag, tagScheme, decrypted)); 
                    }
                    // cryptogram (plain value encoded in BER-TLV, but not including SM DOs)
                    else if (obj.Tag == Tag.Context(0x05, ASN1.PC.Primitive))
                    {
                        // проверить возможность шифрования
                        if (cipherParameters == null) return new Response(0x6988);

                        // plain value encoded in BER-TLV, but not including SM DOs
                        Tag tag = Tag.Context(0x13, ASN1.PC.Constructed);

                        // расшифровать данные
                        byte[] decrypted = Decrypt(cipherParameters, obj.Content, SecureType.BERTLV); 

                        // закодировать данные
                        result.Add(new DataObjectTemplate(Authority.ISO7816, tag, tagScheme, decrypted)); 
                    }
                    // сryptogram (plain value encoded in BER-TLV and including SM DOs
                    else if (obj.Tag == Tag.Context(0x02, ASN1.PC.Primitive))
                    {
                        // проверить возможность шифрования
                        if (cipherParameters == null) return new Response(0x6988);

                        // plain value encoded in BER-TLV and including SM DOs
                        Tag tag = Tag.Context(0x10, ASN1.PC.Constructed);

                        // расшифровать данные
                        byte[] decrypted = Decrypt(cipherParameters, obj.Content, SecureType.BERTLVSM); 

                        // закодировать данные
                        result.Add(new DataObjectTemplate(Authority.ISO7816, tag, tagScheme, decrypted)); 
                    }
                    // сryptogram (plain value encoded in BER-TLV and including SM DOs
                    else if (obj.Tag == Tag.Context(0x03, ASN1.PC.Primitive))
                    {
                        // проверить возможность шифрования
                        if (cipherParameters == null) return new Response(0x6988);

                        // plain value encoded in BER-TLV and including SM DOs
                        Tag tag = Tag.Context(0x11, ASN1.PC.Constructed);

                        // расшифровать данные
                        byte[] decrypted = Decrypt(cipherParameters, obj.Content, SecureType.BERTLVSM); 

                        // закодировать данные
                        result.Add(new DataObjectTemplate(Authority.ISO7816, tag, tagScheme, decrypted)); 
                    }
                    else result.Add(obj); 
                }
                // обработать возможное исключение 
                catch { return new Response(0x6988); }
            }
            // закодировать объекты
            return new Response(DataObject.Encode(tagScheme, result), sw);
        }
    }
}
