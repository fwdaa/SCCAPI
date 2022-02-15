package aladdin.iso7816;
import aladdin.iso7816.ber.*;
import aladdin.asn1.*;
import aladdin.util.*; 
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////////
// Реализация криптографических операций через карту
///////////////////////////////////////////////////////////////////////////////
public class SecureModule extends SecureClient
{
    // используемый канал и криптографическое окружение
    private final LogicalChannel channel; private final SecurityEnvironment environment;
    
    // конструктор
    public SecureModule(LogicalChannel channel)
    { 
        // сохранить переданные параметры
        this.channel = channel; environment = SecurityEnvironment.CURRENT; 
    }
    // получить параметры алгоритма
    public final CRT.AT getAuthenticationParameters() throws IOException 
    {
        // получить параметры алгоритма
        return environment.getAuthenticationParameters(channel); 
    }
    // установить параметры алгоритма
    public final void setAuthenticationParameters(Iterable<DataObject> objs) throws IOException 
    {
        // установить параметры алгоритма
        environment.setAuthenticationParameters(channel, SecureType.NONE, null, objs);
    }
    // получить параметры алгоритма
    public final CRT.HT getHashParameters() throws IOException 
    {
        // получить параметры алгоритма
        return environment.getHashParameters(channel); 
    }
    // установить параметры алгоритма
    public final void setHashParameters(Iterable<DataObject> objs) throws IOException 
    {
        // установить параметры алгоритма
        environment.setHashParameters(channel, SecureType.NONE, null, objs);
    }
    // получить параметры алгоритма
    public final CRT.CCT getMacParameters() throws IOException 
    {
        // получить параметры алгоритма
        return environment.getMacParameters(channel); 
    }
    // установить параметры алгоритма
    public final void setMacParameters(Iterable<DataObject> objs) throws IOException 
    {
        // установить параметры алгоритма
        environment.setMacParameters(channel, SecureType.NONE, null, objs);
    }
    // получить параметры алгоритма
    public final CRT.CT getCipherParameters() throws IOException 
    {
        // получить параметры алгоритма
        return environment.getCipherParameters(channel); 
    }
    // установить параметры алгоритма
    public final void setCipherParameters(Iterable<DataObject> objs) throws IOException 
    {
        // установить параметры алгоритма
        environment.setCipherParameters(channel, SecureType.NONE, null, objs);
    }
    // получить параметры алгоритма
    public final CRT.DST getSignParameters() throws IOException 
    {
        // получить параметры алгоритма
        return environment.getSignParameters(channel); 
    }
    // установить параметры алгоритма
    public final void setSignParameters(Iterable<DataObject> objs) throws IOException 
    {
        // установить параметры алгоритма
        environment.setSignParameters(channel, SecureType.NONE, null, objs);
    }
    // получить параметры алгоритма
    public final CRT.KAT getKeyAgreementParameters() throws IOException 
    {
        // получить параметры алгоритма
        return environment.getKeyAgreementParameters(channel); 
    }
    // установить параметры алгоритма
    public final void setKeyAgreementParameters(Iterable<DataObject> objs) throws IOException 
    {
        // установить параметры алгоритма
        environment.setKeyAgreementParameters(channel, SecureType.NONE, null, objs);
    }
    // размер блока при вычислении имитовставки и подписи
    public int checksumBlockSize() { return 1; } 
    public int signBlockSize    () { return 1; } 
    
    // объединить данные
    private byte[] concat(byte[][] data, int blockSize)
    {
        // указать начальные условия
        byte[] buffer = (data.length > 0) ? data[0] : new byte[0]; 
                
        // для всех частей данных
        for (int i = 1; i < data.length; i++)
        {
            // сохранить размер буфера
            int position = buffer.length; 
            
            // определить новый размер буфера
            int length = (position + blockSize) / blockSize * blockSize; 
            
            // изменить размер буфера
            buffer = Arrays.copyOf(buffer, length); buffer[position] = (byte)0x80;
            
            // скопировать часть данных
            System.arraycopy(data[i], 0, buffer, length, data[i].length);
        }
        return buffer; 
    }
    // захэшировать данные
    @SuppressWarnings("try")
    @Override public byte[] hash(CRT.HT parameters, byte[] data) throws IOException
    {
        // при отсутствии дополнительных параметров
        if (parameters == null)
        {
            // захэшировать данные
            Response response = channel.sendCommand(
                INS.PERFORM_SECURITY_OPERATION, (byte)0x90, (byte)0x80, data, -1
            ); 
            // проверить отсутствие ошибок
            ResponseException.check(response); return response.data; 
        }
        // заблокировать карту
        try (CardLock cardLock = new CardLock(channel.session()))
        {
            // получить параметры алгоритма
            CRT.HT oldParameters = getHashParameters(); 
                
            // переустановить параметры алгоритма
            setHashParameters(parameters); 
            try { 
                // захэшировать данные
                return hash(null, data); 
            }
            // восстановить параметры алгоритма
            finally { setHashParameters(oldParameters); }
        }
    }
    // вычислить контрольную сумму
    @SuppressWarnings("try")
    @Override public byte[] checksum(CRT.CCT parameters, byte[][] data) throws IOException
    {
        // при отсутствии дополнительных параметров
        if (parameters == null)
        {
            // объединить данные
            byte[] buffer = concat(data, checksumBlockSize()); 
            
            // вычислить контрольную сумму
            Response response = channel.sendCommand(
                INS.PERFORM_SECURITY_OPERATION, (byte)0x8E, (byte)0x80, buffer, -1
            ); 
            // проверить отсутствие ошибок
            ResponseException.check(response); return response.data; 
        }
        // заблокировать карту
        try (CardLock cardLock = new CardLock(channel.session()))
        {
            // получить параметры алгоритма
            CRT.CCT oldParameters = getMacParameters(); 
                
            // переустановить параметры алгоритма
            setMacParameters(parameters); 
            try { 
                // вычислить контрольную сумму
                return checksum(null, data); 
            }
            // восстановить параметры алгоритма
            finally { setMacParameters(oldParameters); }
        }
    }
    // зашифровать данные
    @SuppressWarnings("try")
    @Override public byte[] encrypt(CRT.CT parameters, byte[] data, int secureType) throws IOException
    {
        // при отсутствии дополнительных параметров
        if (parameters == null) { byte outputType = (byte)0x86; 
        
            // указать код команды
            if ((secureType & SecureType.BERTLV) != 0) { outputType = (byte)0x84; 
            
                // указать код команды
                if ((secureType & SecureType.BERTLV_SM) == SecureType.BERTLV_SM) outputType = (byte)0x82; 
            }
            // зашифровать данные
            Response response = channel.sendCommand(
                INS.PERFORM_SECURITY_OPERATION, outputType, (byte)0x80, data, -1
            ); 
            // проверить отсутствие ошибок
            ResponseException.check(response); return response.data; 
        }
        // заблокировать карту
        try (CardLock cardLock = new CardLock(channel.session()))
        {
            // получить параметры алгоритма
            CRT.CT oldParameters = getCipherParameters(); 
                
            // переустановить параметры алгоритма
            setCipherParameters(parameters); 
            try { 
                // зашифровать данные
                return encrypt(null, data, secureType); 
            }
            // восстановить параметры алгоритма
            finally { setCipherParameters(oldParameters); }
        }
    }
    // расшифровать данные
    @SuppressWarnings("try")
    @Override public byte[] decrypt(CRT.CT parameters, byte[] data, int secureType) throws IOException
    {
        // при отсутствии дополнительных параметров
        if (parameters == null) { byte inputType = (byte)0x86; 
        
            // указать код команды
            if ((secureType & SecureType.BERTLV) != 0) { inputType = (byte)0x84; 
            
                // указать код команды
                if ((secureType & SecureType.BERTLV_SM) == SecureType.BERTLV_SM) inputType = (byte)0x82; 
            }
            // расшифровать данные
            Response response = channel.sendCommand(
                INS.PERFORM_SECURITY_OPERATION, (byte)0x80, inputType, data, -1
            ); 
            // проверить отсутствие ошибок
            ResponseException.check(response); return response.data; 
        }
        // заблокировать карту
        try (CardLock cardLock = new CardLock(channel.session()))
        {
            // получить параметры алгоритма
            CRT.CT oldParameters = getCipherParameters(); 
                
            // переустановить параметры алгоритма
            setCipherParameters(parameters); 
            try { 
                // расшифровать данные
                return decrypt(null, data, secureType); 
            }
            // восстановить параметры алгоритма
            finally { setCipherParameters(oldParameters); }
        }
    }
    // подписать данные
    @SuppressWarnings("try")
    @Override public byte[] sign(CRT.DST parameters, byte[][] data) throws IOException
    {
        // при отсутствии дополнительных параметров
        if (parameters == null)
        {
            // объединить данные
            byte[] buffer = concat(data, signBlockSize()); 
            
            // подписать данные
            Response response = channel.sendCommand(
                INS.PERFORM_SECURITY_OPERATION, (byte)0x9E, (byte)0x9A, buffer, -1
            ); 
            // проверить отсутствие ошибок
            ResponseException.check(response); return response.data; 
        }
        // заблокировать карту
        try (CardLock cardLock = new CardLock(channel.session()))
        {
            // получить параметры алгоритма
            CRT.DST oldParameters = getSignParameters(); 
                
            // переустановить параметры алгоритма
            setSignParameters(parameters); 
            try { 
                // подписать данные
                return sign(null, data); 
            }
            // восстановить параметры алгоритма
            finally { setSignParameters(oldParameters); }
        }
    }
    // проверить подпись данных
    @SuppressWarnings("try")
    @Override public void verify(CRT.DST parameters, byte[][] data, byte[] sign) throws IOException
    {
        // при отсутствии дополнительных параметров
        if (parameters == null)
        {
            // объединить данные
            byte[] buffer = concat(data, signBlockSize()); 
            
            // закодировать данные
            IEncodable encodedData = Encodable.encode(
                aladdin.asn1.Tag.context(0x1A), PC.PRIMITIVE, buffer
            ); 
            // закодировать подпись
            IEncodable encodedSign = Encodable.encode(
                aladdin.asn1.Tag.context(0x1E), PC.PRIMITIVE, sign
            ); 
            // объединить данные и подпись
            byte[] encoded = Array.concat(encodedData.encoded(), encodedSign.encoded()); 
            
            // подписать данные
            Response response = channel.sendCommand(
                INS.PERFORM_SECURITY_OPERATION, (byte)0x00, (byte)0xA8, encoded, 0
            ); 
            // проверить отсутствие ошибок
            ResponseException.check(response); return; 
        }
        // заблокировать карту
        try (CardLock cardLock = new CardLock(channel.session()))
        {
            // получить параметры алгоритма
            CRT.DST oldParameters = getSignParameters(); 
                
            // переустановить параметры алгоритма
            setSignParameters(parameters); 
            try { 
                // проверить подпись данных
                verify(null, data, sign);  
            }
            // восстановить параметры алгоритма
            finally { setSignParameters(oldParameters); }
        }
    }
}
