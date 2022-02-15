using System;
using System.IO;
using System.Globalization;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Идентификатор приложения (0x4F)
    ///////////////////////////////////////////////////////////////////////////
    public class ApplicationIdentifier : DataObject
    {
        // раскодировать идентификатор
        public static ApplicationIdentifier Decode(byte[] content)
        {
            // проверить корректность размера
            if (content.Length == 0) throw new InvalidDataException();

            // раскодировать идентификатор
            if ((content[0] >> 4) == 0x0A) return new International(content); 
            if ((content[0] >> 4) == 0x0D) return new National     (content); 
            if ((content[0] >> 0) == 0xE8) return new Standard     (content); 
            if ((content[0] >> 4) == 0x0F) return new Proprietary  (content); 
            
            // неизвестный идентификатор
            return new ApplicationIdentifier(content); 
        }
        // конструктор
        public ApplicationIdentifier(byte[] content) : base(Authority.ISO7816, ISO7816.Tag.ApplicationIdentifier, content) 
        {
            // проверить корректность размера
            if (content.Length == 0) throw new InvalidDataException(); 
        }
        // конструктор закодирования
        protected ApplicationIdentifier() : base(Authority.ISO7816, ISO7816.Tag.ApplicationIdentifier) {}

        ///////////////////////////////////////////////////////////////////////
        // Незарегистрированный идентификатор
        ///////////////////////////////////////////////////////////////////////
        public class Proprietary : ApplicationIdentifier
        {
            // конструктор
            public Proprietary(byte[] content) : base(content) 
            {            
                // проверить корректность размера
                if (content.Length > 16) throw new InvalidDataException(); 
                
                // проверить корректность
                if ((content[0] & 0xF0) != 0xF0) throw new InvalidDataException(); 
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Идентификатор стандарта
        ///////////////////////////////////////////////////////////////////////
        public class Standard : ApplicationIdentifier
        {
            // зарегистрированный идентификатор и дополнительные байты
            public readonly ASN1.ObjectIdentifier OID; public readonly byte[] Extension;

            // конструктор закодирования
            public Standard(string oid, byte[] extension)
            {
                // сохранить переданные параметры
                OID = new ASN1.ObjectIdentifier(oid); Extension = extension; 
                
                // проверить корректность данных
                if (extension.Length > 15 - OID.Content.Length) throw new ArgumentException();
            }
            // конструктор раскодирования
            public Standard(byte[] content) : base(content)
            {
                // проверить корректность размера
                if (content.Length > 16) throw new InvalidDataException();

                // проверить корректность данных
                if (content[0] != 0xE8) throw new InvalidDataException();

                // раскодированный идентификатор
                ASN1.ObjectIdentifier decoded = null; int size = content.Length - 1; 
            
                // для всевозможных размеров
                for (; size >= 1; size--)
                try {
                    // извлечь возможное содержимое OID
                    byte[] buffer = new byte[size]; Array.Copy(content, 1, buffer, 0, size);
                
                    // раскодировать идентификатор
                    decoded = new ASN1.ObjectIdentifier(ASN1.Encodable.Encode(
                        ASN1.Tag.ObjectIdentifier, ASN1.PC.Primitive, buffer
                    ));
                    break; 
                }
                // проверить наличие идентификатора
                catch {} if (decoded == null) throw new IOException(); 
            
                // сохранить раскодированный идентификатор
                OID = decoded; Extension = new byte[content.Length - 1 - size];

                // сохранить дополнительные байты
                Array.Copy(content, content.Length - Extension.Length, Extension, 0, Extension.Length); 
            }
            // закодированное представление
            public override byte[] Content { get { byte[] contentOID = OID.Content;

                // выделить память для представления
                byte[] encoded = new byte[1 + contentOID.Length + Extension.Length]; 

                // скопировать закодированный идентификатор
                encoded[0] = 0xE8; Array.Copy(contentOID, 0, encoded, 1, contentOID.Length); 

                // скопировать дополнительные байты
                Array.Copy(Extension, 0, encoded, 1 + contentOID.Length, Extension.Length); return encoded; 
            }} 
        }
        ///////////////////////////////////////////////////////////////////////
        // Национальный идентификатор
        ///////////////////////////////////////////////////////////////////////
        public class National : ApplicationIdentifier
        {
            // описание региона
            public readonly RegionInfo Region; 

            // идентификатор и дополнительные байты
            public readonly int RID; public readonly byte[] PIX; 

            // конструктор закодирования
            public National(RegionInfo region, int rid, byte[] pix)
            {
                // проверить корректность данных
                if (rid >= 1000000 || pix.Length > 11) 
                {
                    // при ошибке выбросить исключение
                    throw new ArgumentException();
                }
                // сохранить переданные параметры
                Region = region; RID = rid; PIX = pix; 
            }
            // конструктор раскодирования
            public National(byte[] content)
            {
                // проверить корректность данных
                if (content.Length < 5 || content.Length > 16) 
                {
                    // при ошибке выбросить исключение
                    throw new InvalidDataException(); 
                }
                // проверить тип данных
                if ((content[0] >> 4) != 0xD || (content[0] & 0xF) > 9) 
                {
                    // при ошибке выбросить исключение
                    throw new InvalidDataException(); 
                }
                // извлечь 8 цифр
                int[] digits = Encoding.DecodeDigits(8, content, 1); 

                // извлечь код страны
                int code = (content[0] & 0xF) * 100 + (content[1] >> 4) * 10 + (content[1] & 0xF); 

                // получить описание региона
                Region = CountryIndicator.GetRegionInfo(code); 
                
                // проверить отсутствие ошибок
                if (Region == null) throw new InvalidDataException(); int value = 0; 
            
                // вычиcлить идентификатор
                for (int i = 2; i < 8; i++) value = value * 10 + digits[i]; 

                // выделить память для дополнительных байтов
                RID = value; PIX = new byte[content.Length - 5];
                
                // скопировать дополнительные байты
                Array.Copy(content, 5, PIX, 0, PIX.Length); 
            }
            // закодированное представление
            public override byte[] Content { get { 

                // выделить память для закодированного представления
                byte[] encoded = new byte[5 + PIX.Length]; 

                // получить код региона
                int code = CountryIndicator.GetCountryCode(Region); 

                // закодировать первый байт
                encoded[0] = (byte)(0xD0 | (code / 100)); code %= 100; 

                // закодировать второй байт
                encoded[1] = (byte)(((code / 10) << 4) | (code % 10)); 

                // указать кодируемые цифры
                int[] digits = new int[6]; for (int i = 5, value = RID; i >= 0; i--)
                {
                    // указать очередную цифру
                    digits[i] = value % 10; value = (value - digits[i]) / 10; 
                }
                // закодировать идентификатор
                Encoding.EncodeDigits(digits, encoded, 2);

                // скопировать дополнительные байты
                Array.Copy(PIX, 0, encoded, 5, PIX.Length); return encoded; 
            }}
        }
        ///////////////////////////////////////////////////////////////////////
        // Международный идентификатор
        ///////////////////////////////////////////////////////////////////////
        public class International : ApplicationIdentifier
        {
            // идентификатор и дополнительные байты
            public readonly int RID; public readonly byte[] PIX; 

            // конструктор закодирования
            public International(int rid, byte[] pix)
            {
                // проверить корректность данных
                if (rid >= 1000000000 || pix.Length > 11) 
                {
                    // при ошибке выбросить исключение
                    throw new ArgumentException();
                }
                // сохранить переданные параметры
                RID = rid; PIX = pix; 
            }
            // конструктор раскодирования
            public International(byte[] content)
            {
                // проверить корректность данных
                if (content.Length < 5 || content.Length > 16) 
                {
                    // при ошибке выбросить исключение
                    throw new InvalidDataException(); 
                }
                // проверить тип данных
                if ((content[0] >> 4) != 0xA || (content[0] & 0xF) > 9) 
                {
                    // при ошибке выбросить исключение
                    throw new InvalidDataException(); 
                }
                // извлечь 8 цифр
                int[] digits = Encoding.DecodeDigits(8, content, 1); 
                
                // указать первую цифру идентификатора
                int value = (content[0] & 0xF) * 100000000; 
            
                // вычилить идентификатор
                for (int i = 0; i < 8; i++) value = value * 10 + digits[i]; 

                // выделить память для дополнительных байтов
                RID = value; PIX = new byte[content.Length - 5];
                
                // скопировать дополнительные байты
                Array.Copy(content, 5, PIX, 0, PIX.Length); 
            }
            // закодированное представление
            public override byte[] Content { get 
            { 
                // выделить память для закодированного представления
                byte[] encoded = new byte[5 + PIX.Length]; 

                // закодировать первый байт
                encoded[0] = (byte)(0xA0 | (RID / 100000000)); 

                // указать кодируемые цифры
                int[] digits = new int[8]; for (int i = 7, value = RID; i >= 0; i--)
                {
                    // указать очередную цифру
                    digits[i] = value % 10; value = (value - digits[i]) / 10; 
                }
                // закодировать идентификатор
                Encoding.EncodeDigits(digits, encoded, 1);

                // скопировать дополнительные байты
                Array.Copy(PIX, 0, encoded, 5, PIX.Length); return encoded; 
            }}
        }
    }
}
