package aladdin.capi;
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Кодировка сертификатов, списков отозванных сертификатов и запросов на сертификат
///////////////////////////////////////////////////////////////////////////
public abstract class PEM
{
    // закодировать данные
    public static String encode(byte[] encoded, String objectName) 
    { 
        // получить символ перевода строки
        String nl = System.getProperty("line.separator"); 
        
        // получить представление Base64
        String content = Base64.getEncoder().encodeToString(encoded); 

        // создать строковый буфер
        StringBuilder buffer = new StringBuilder(); 

        // указать заголовок сертификата
        buffer.append(String.format("-----BEGIN %1$s-----%2$s", objectName, nl)); 

        // для всех 64-символьных подстрок
        for (int i = 0; i < content.length() / 64; i++)
        {
            // извлечь подстроку
            String substr = content.substring(i * 64, (i + 1)* 64); 

            // поместить 64-символьную подстроку
            buffer.append(String.format("%1$s%2$s", substr, nl)); 
        }
        // при наличии неполной подстроки
        if ((content.length() % 64) != 0)
        {
            // извлечь подстроку
            String substr = content.substring((content.length() / 64) * 64); 

            // поместить 64-символьную подстроку
            buffer.append(String.format("%1$s%2$s", substr, nl)); 
        }
        // указать завершение сертификата
        buffer.append(String.format("-----END %1$s-----%2$s", objectName, nl)); 
                
        // вернуть строковое представление
        return buffer.toString(); 
    }
    // раскодировать данные
    public static byte[] decode(String encoded) throws IOException
    {
        // раскодировать данные
        return decode(encoded.getBytes("ASCII")); 
    }
    // раскодировать данные
    public static byte[] decode(byte[] encoded) throws IOException
    {
        // создать поток данных
        try (InputStream stream = new ByteArrayInputStream(encoded))
        {
            // раскодировать данные
            return decode(stream); 
        }
    }
    // раскодировать данные
    public static byte[] decode(InputStream stream) throws IOException
    {
        // прочитать следующий байт
        int first = stream.read(); if (first < 0) throw new IOException(); 

        // раскодировать объект
        return decode(stream, (byte)first); 
    }
    // раскодировать данные
    public static byte[] decode(InputStream stream, byte first) throws IOException
    {
        // проверить корректность формата
        int next = first & 0xFF; if (next != '-') throw new IOException(); 
        
        // создать динамический буфер
        StringBuilder buffer = new StringBuilder(); 
        
        // пропустить строку
        while (next >= 0 && next != '\r' && next != '\n') next = stream.read();
        
        // прочитать следующий символ
        if (next == '\r') { next = stream.read(); 
        
            // прочитать следующий символ
            if (next == '\n') next = stream.read(); 
        }
        // прочитать следующий символ
        else if (next >= 0) next = stream.read(); 
        
        // для всех байтов потока
        while (next >= 0 && next != '-')
        {
            // при наличии символа кодировки Base-64
            for (; next >= 0 && next != '\r' && next != '\n'; next = stream.read())
            {
                // сохранить символ кодировки Base-64
                if (next != ' ' && next != '\t') buffer.append((char)next);
            }
            // прочитать следующий символ
            if (next == '\r') { next = stream.read(); 

                // прочитать следующий символ
                if (next == '\n') next = stream.read(); 
            }
            // прочитать следующий символ
            else if (next >= 0) next = stream.read(); 
        }
        // раскодировать строку
        return Base64.getDecoder().decode(buffer.toString()); 
    }
}
