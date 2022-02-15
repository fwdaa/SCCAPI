package aladdin.iso7816;
import aladdin.iso7816.ber.*;
import aladdin.asn1.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Криптографическая среда
///////////////////////////////////////////////////////////////////////////////
public class SecurityEnvironment 
{
    // текущая криптографическая среда
    public static final SecurityEnvironment CURRENT = new SecurityEnvironment(); 
    
    // установить криптографическую среду
    public static SecurityEnvironment select(LogicalChannel channel, 
        int secureType, SecureClient secureClient, int id) throws IOException
    {
        // проверить корректность идентификатора
        if (id < 0 || id > 255) throw new IllegalArgumentException(); 
        
        // выполнить команду
        Response response = channel.sendCommand(secureType, secureClient, 
            INS.MANAGE_SECURITY_ENVIRONMENT, (byte)0xF3, (byte)id, new byte[0], 0
        ); 
        // проверить отсутствие ошибок
        ResponseException.check(response); return CURRENT;
    }
    // установить криптографическую среду по умолчанию
    public static SecurityEnvironment selectDefault(LogicalChannel channel, 
        int secureType, SecureClient secureClient, int id) throws IOException
    {
        // выполнить команду
        Response response = channel.sendCommand(secureType, secureClient, 
            INS.MANAGE_SECURITY_ENVIRONMENT, (byte)0xF7, (byte)0x00, new byte[0], 0
        ); 
        // проверить отсутствие ошибок
        ResponseException.check(response); return CURRENT;
    }
    // установить криптографическую среду
    public static SecurityEnvironment selectEmpty(LogicalChannel channel, 
        int secureType, SecureClient secureClient) throws IOException
    {
        // выполнить команду
        Response response = channel.sendCommand(secureType, secureClient, 
            INS.MANAGE_SECURITY_ENVIRONMENT, (byte)0xF3, (byte)0x00, new byte[0], 0
        ); 
        // проверить отсутствие ошибок
        ResponseException.check(response); return CURRENT;
    }
    // установить криптографическую среду
    public SecurityEnvironment selectDenied(LogicalChannel channel, 
        int secureType, SecureClient secureClient) throws IOException
    {
        // выполнить команду
        Response response = channel.sendCommand(secureType, secureClient, 
            INS.MANAGE_SECURITY_ENVIRONMENT, (byte)0xF3, (byte)0xFF, new byte[0], 0
        ); 
        // проверить отсутствие ошибок
        ResponseException.check(response); return CURRENT;
    }
    // удалить криптографическую среду
    public static void erase(LogicalChannel channel, 
        int secureType, SecureClient secureClient, int id) throws IOException
    {
        // проверить корректность идентификатора
        if (id < 0 || id > 255) throw new IllegalArgumentException(); 
        
        // выполнить команду
        Response response = channel.sendCommand(secureType, secureClient, 
            INS.MANAGE_SECURITY_ENVIRONMENT, (byte)0xF4, (byte)id, new byte[0], 0
        ); 
        // проверить отсутствие ошибок
        ResponseException.check(response);
    }
    // сохранить криптографическую среду
    public final void store(LogicalChannel channel, 
        int secureType, SecureClient secureClient, int id) throws IOException
    {
        // проверить корректность идентификатора
        if (id < 0 || id > 255) throw new IllegalArgumentException(); 
        
        // выполнить команду
        Response response = channel.sendCommand(secureType, secureClient, 
            INS.MANAGE_SECURITY_ENVIRONMENT, (byte)0xF2, (byte)id, new byte[0], 0
        ); 
        // проверить отсутствие ошибок
        ResponseException.check(response);
    }
    // получить всю информацию
    public final SE getInfo(LogicalChannel channel) throws IOException 
    {
        // указать схему кодирования
        TagScheme tagScheme = channel.environment().tagScheme(); 
        
        // выполнить команду
        Response response = channel.sendCommand(SecureType.NONE, null, 
            INS.MANAGE_SECURITY_ENVIRONMENT, (byte)0x00, (byte)0x00, new byte[0], -1
        ); 
        // проверить отсутствие ошибок
        ResponseException.check(response);
        
        // раскодировать объект
        return new SE(tagScheme, response.data); 
    }
    // получить параметры алгоритма
    public final CRT.AT getAuthenticationParameters(LogicalChannel channel) throws IOException 
    {
        // указать схему кодирования
        TagScheme tagScheme = channel.environment().tagScheme(); 
        
        // указать тип объекта
        Tag tag = Tag.context(0x04, PC.CONSTRUCTED); 
        
        // выполнить команду
        Response response = channel.sendCommand(SecureType.NONE, null,
            INS.MANAGE_SECURITY_ENVIRONMENT, (byte)0x08, (byte)0xA4, new byte[0], -1
        ); 
        // проверить отсутствие ошибок
        ResponseException.check(response);
        
        // раскодировать объект
        return new CRT.AT(tag, tagScheme, response.data); 
    }
    // установить параметры алгоритма
    public final void setAuthenticationParameters(LogicalChannel channel, 
        int secureType, SecureClient secureClient, 
        Iterable<DataObject> objs) throws IOException 
    {
        // указать схему кодирования
        TagScheme tagScheme = channel.environment().tagScheme(); 
        
        // закодировать объекты
        byte[] encoded = DataObject.encode(tagScheme, objs); 
        
        // выполнить команду
        Response response = channel.sendCommand(secureType, secureClient, 
            INS.MANAGE_SECURITY_ENVIRONMENT, (byte)0x01, (byte)0xA4, encoded, 0
        ); 
        // проверить отсутствие ошибок
        ResponseException.check(response);
    }
    // получить параметры алгоритма
    public final CRT.HT getHashParameters(LogicalChannel channel) throws IOException 
    {
        // указать схему кодирования
        TagScheme tagScheme = channel.environment().tagScheme(); 
        
        // указать тип объекта
        Tag tag = Tag.context(0x0A, PC.CONSTRUCTED); 
            
        // выполнить команду
        Response response = channel.sendCommand(SecureType.NONE, null, 
            INS.MANAGE_SECURITY_ENVIRONMENT, (byte)0x08, (byte)0xAA, new byte[0], -1
        ); 
        // проверить отсутствие ошибок
        ResponseException.check(response);
        
        // раскодировать объект
        return new CRT.HT(tag, tagScheme, response.data); 
    }
    // установить параметры алгоритма
    public final void setHashParameters(LogicalChannel channel, 
        int secureType, SecureClient secureClient, 
        Iterable<DataObject> objs) throws IOException 
    {
        // указать схему кодирования
        TagScheme tagScheme = channel.environment().tagScheme(); 
        
        // закодировать объекты
        byte[] encoded = DataObject.encode(tagScheme, objs); 
        
        // выполнить команду
        Response response = channel.sendCommand(secureType, secureClient, 
            INS.MANAGE_SECURITY_ENVIRONMENT, (byte)0x01, (byte)0xAA, encoded, 0
        ); 
        // проверить отсутствие ошибок
        ResponseException.check(response);
    }
    // получить параметры алгоритма
    public final CRT.CCT getMacParameters(LogicalChannel channel) throws IOException 
    {
        // указать схему кодирования
        TagScheme tagScheme = channel.environment().tagScheme(); 
        
        // указать тип объекта
        Tag tag = Tag.context(0x14, PC.CONSTRUCTED); 
            
        // выполнить команду
        Response response = channel.sendCommand(SecureType.NONE, null, 
            INS.MANAGE_SECURITY_ENVIRONMENT, (byte)0x08, (byte)0xB4, new byte[0], -1
        ); 
        // проверить отсутствие ошибок
        ResponseException.check(response);
        
        // раскодировать объект
        return new CRT.CCT(tag, tagScheme, response.data); 
    }
    // установить параметры алгоритма
    public final void setMacParameters(LogicalChannel channel, 
        int secureType, SecureClient secureClient, 
        Iterable<DataObject> objs) throws IOException 
    {
        // указать схему кодирования
        TagScheme tagScheme = channel.environment().tagScheme(); 
        
        // закодировать объекты
        byte[] encoded = DataObject.encode(tagScheme, objs); 
        
        // выполнить команду
        Response response = channel.sendCommand(secureType, secureClient, 
            INS.MANAGE_SECURITY_ENVIRONMENT, (byte)0x01, (byte)0xB4, encoded, 0
        ); 
        // проверить отсутствие ошибок
        ResponseException.check(response);
    }
    // получить параметры алгоритма
    public final CRT.CT getCipherParameters(LogicalChannel channel) throws IOException 
    {
        // указать схему кодирования
        TagScheme tagScheme = channel.environment().tagScheme(); 
        
        // указать тип объекта
        Tag tag = Tag.context(0x18, PC.CONSTRUCTED); 
            
        // выполнить команду
        Response response = channel.sendCommand(SecureType.NONE, null, 
            INS.MANAGE_SECURITY_ENVIRONMENT, (byte)0x08, (byte)0xB8, new byte[0], -1
        ); 
        // проверить отсутствие ошибок
        ResponseException.check(response);
        
        // раскодировать объект
        return new CRT.CT(tag, tagScheme, response.data); 
    }
    // установить параметры алгоритма
    public final void setCipherParameters(LogicalChannel channel, 
        int secureType, SecureClient secureClient, 
        Iterable<DataObject> objs) throws IOException 
    {
        // указать схему кодирования
        TagScheme tagScheme = channel.environment().tagScheme(); 
        
        // закодировать объекты
        byte[] encoded = DataObject.encode(tagScheme, objs); 
        
        // выполнить команду
        Response response = channel.sendCommand(secureType, secureClient, 
            INS.MANAGE_SECURITY_ENVIRONMENT, (byte)0x01, (byte)0xB8, encoded, 0
        ); 
        // проверить отсутствие ошибок
        ResponseException.check(response);
    }
    // получить параметры алгоритма
    public final CRT.DST getSignParameters(LogicalChannel channel) throws IOException 
    {
        // указать схему кодирования
        TagScheme tagScheme = channel.environment().tagScheme(); 
        
        // указать тип объекта
        Tag tag = Tag.context(0x16, PC.CONSTRUCTED); 
            
        // выполнить команду
        Response response = channel.sendCommand(SecureType.NONE, null, 
            INS.MANAGE_SECURITY_ENVIRONMENT, (byte)0x08, (byte)0xB6, new byte[0], -1
        ); 
        // проверить отсутствие ошибок
        ResponseException.check(response);
        
        // раскодировать объект
        return new CRT.DST(tag, tagScheme, response.data); 
    }
    // установить параметры алгоритма
    public final void setSignParameters(LogicalChannel channel, 
        int secureType, SecureClient secureClient, 
        Iterable<DataObject> objs) throws IOException 
    {
        // указать схему кодирования
        TagScheme tagScheme = channel.environment().tagScheme(); 
        
        // закодировать объекты
        byte[] encoded = DataObject.encode(tagScheme, objs); 
        
        // выполнить команду
        Response response = channel.sendCommand(secureType, secureClient, 
            INS.MANAGE_SECURITY_ENVIRONMENT, (byte)0x01, (byte)0xB6, encoded, 0
        ); 
        // проверить отсутствие ошибок
        ResponseException.check(response);
    }
    // получить параметры алгоритма
    public final CRT.KAT getKeyAgreementParameters(LogicalChannel channel) throws IOException 
    {
        // указать схему кодирования
        TagScheme tagScheme = channel.environment().tagScheme(); 
        
        // указать тип объекта
        Tag tag = Tag.context(0x06, PC.CONSTRUCTED); 
            
        // выполнить команду
        Response response = channel.sendCommand(SecureType.NONE, null, 
            INS.MANAGE_SECURITY_ENVIRONMENT, (byte)0x08, (byte)0xA6, new byte[0], -1
        ); 
        // проверить отсутствие ошибок
        ResponseException.check(response);
        
        // раскодировать объект
        return new CRT.KAT(tag, tagScheme, response.data); 
    }
    // установить параметры алгоритма
    public final void setKeyAgreementParameters(LogicalChannel channel, 
        int secureType, SecureClient secureClient, 
        Iterable<DataObject> objs) throws IOException 
    {
        // указать схему кодирования
        TagScheme tagScheme = channel.environment().tagScheme(); 
        
        // закодировать объекты
        byte[] encoded = DataObject.encode(tagScheme, objs); 
        
        // выполнить команду
        Response response = channel.sendCommand(secureType, secureClient, 
            INS.MANAGE_SECURITY_ENVIRONMENT, (byte)0x01, (byte)0xA6, encoded, 0
        ); 
        // проверить отсутствие ошибок
        ResponseException.check(response);
    }
}
