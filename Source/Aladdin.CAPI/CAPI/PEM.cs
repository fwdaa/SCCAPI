using System;
using System.IO;
using System.Text;

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Кодировка сертификатов, списков отозванных сертификатов и запросов на сертификат
    ///////////////////////////////////////////////////////////////////////////
    public static class PEM
    {
        // закодировать данные в PEM-кодировке
        public static string Encode(byte[] encoded, string objectName) 
        { 
            // указать символ перевода строки
            string nl = Environment.NewLine; 

            // получить представление Base64
            string content = Base64.GetEncoder().EncodeToString(encoded); 

            // создать строковый буфер
            StringBuilder buffer = new StringBuilder(); 

            // указать заголовок сертификата
            buffer.Append(String.Format("-----BEGIN {0}-----{1}", objectName, nl)); 

            // для всех 64-символьных подстрок
            for (int i = 0; i < content.Length / 64; i++)
            {
                // извлечь подстроку
                string substr = content.Substring(i * 64, 64); 

                // поместить 64-символьную подстроку
                buffer.AppendFormat("{0}{1}", substr, nl); 
            }
            // при наличии неполной подстроки
            if ((content.Length % 64) != 0)
            {
                // извлечь подстроку
                string substr = content.Substring((content.Length / 64) * 64); 

                // поместить 64-символьную подстроку
                buffer.AppendFormat("{0}{1}", substr, nl); 
            }
            // указать завершение сертификата
            buffer.Append(String.Format("-----END {0}-----{1}", objectName, nl)); 
                
            return buffer.ToString();
        } 
        // раскодировать данные
        public static byte[] Decode(string encoded)
        {
            // раскодировать данные
            return Decode(Encoding.ASCII.GetBytes(encoded)); 
        }
        // раскодировать данные
        public static byte[] Decode(byte[] encoded)
        {
            // раскодировать данные
            using (MemoryStream stream = new MemoryStream(encoded)) { return Decode(stream); }
        }
        // раскодировать данные
        public static byte[] Decode(Stream stream)
        {
            // прочитать следующий байт
            int first = stream.ReadByte(); if (first < 0) throw new InvalidDataException(); 

            // раскодировать данные
            return Decode(stream, (byte)first); 
        }
        // раскодировать данные
        public static byte[] Decode(Stream stream, byte first) 
        {
            // проверить корректность формата
            int next = first; if (next != '-') throw new InvalidDataException(); 
        
            // создать динамический буфер
            StringBuilder buffer = new StringBuilder(); 
        
            // пропустить строку
            while (next >= 0 && next != '\r' && next != '\n') next = stream.ReadByte();
        
            // прочитать следующий символ
            if (next == '\r') { next = stream.ReadByte(); 
        
                // прочитать следующий символ
                if (next == '\n') next = stream.ReadByte(); 
            }
            // прочитать следующий символ
            else if (next >= 0) next = stream.ReadByte(); 
        
            // для всех байтов потока
            while (next >= 0 && next != '-')
            {
                // при наличии символа кодировки Base-64
                for (; next >= 0 && next != '\r' && next != '\n'; next = stream.ReadByte())
                {
                    // сохранить символ кодировки Base-64
                    if (next != ' ' && next != '\t') buffer.Append((char)next);
                }
                // прочитать следующий символ
                if (next == '\r') { next = stream.ReadByte(); 

                    // прочитать следующий символ
                    if (next == '\n') next = stream.ReadByte(); 
                }
                // прочитать следующий символ
                else if (next >= 0) next = stream.ReadByte(); 
            }
            // раскодировать строку
            return Base64.GetDecoder().Decode(buffer.ToString()); 
        }
    }
}
