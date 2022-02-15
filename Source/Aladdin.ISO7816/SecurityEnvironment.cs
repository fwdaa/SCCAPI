using System;
using System.Collections.Generic;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////////
    // Криптографическая среда
    ///////////////////////////////////////////////////////////////////////////////
    public class SecurityEnvironment 
    {
        // текущая криптографическая среда
        public static readonly SecurityEnvironment Current = new SecurityEnvironment(); 
    
        // установить криптографическую среду
        public static SecurityEnvironment Select(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, int id)
        {
            // проверить корректность идентификатора
            if (id < 0 || id > 255) throw new ArgumentException(); 
        
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.ManageSecurityEnvironment, 0xF3, (byte)id, new byte[0], 0
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response); return Current;
        }
        // установить криптографическую среду по умолчанию
        public static SecurityEnvironment SelectDefault(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, int id) 
        {
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.ManageSecurityEnvironment, 0xF7, 0x00, new byte[0], 0
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response); return Current;
        }
        // установить криптографическую среду
        public static SecurityEnvironment SelectEmpty(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient) 
        {
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.ManageSecurityEnvironment, 0xF3, 0x00, new byte[0], 0
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response); return Current;
        }
        // установить криптографическую среду
        public SecurityEnvironment SelectDenied(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient) 
        {
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.ManageSecurityEnvironment, 0xF3, 0xFF, new byte[0], 0
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response); return Current;
        }
        // удалить криптографическую среду
        public static void Erase(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, int id) 
        {
            // проверить корректность идентификатора
            if (id < 0 || id > 255) throw new ArgumentException(); 
        
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.ManageSecurityEnvironment, 0xF4, (byte)id, new byte[0], 0
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response); 
        }
        // сохранить криптографическую среду
        public void Store(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, int id)
        {
            // проверить корректность идентификатора
            if (id < 0 || id > 255) throw new ArgumentException(); 
        
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.ManageSecurityEnvironment, 0xF2, (byte)id, new byte[0], 0
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response);
        }
        // получить всю информацию
        public BER.SE GetInfo(LogicalChannel channel) 
        {
            // указать схему кодирования
            TagScheme tagScheme = channel.Environment.TagScheme; 
        
            // выполнить команду
            Response response = channel.SendCommand(SecureType.None, 
                null, INS.ManageSecurityEnvironment, 0x00, 0x00, new byte[0], -1
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response);
        
            // раскодировать объект
            return new BER.SE(tagScheme, response.Data); 
        }
        // получить параметры алгоритма
        public BER.CRT.AT GetAuthenticationParameters(LogicalChannel channel) 
        {
            // указать схему кодирования
            TagScheme tagScheme = channel.Environment.TagScheme; 
        
            // указать тип объекта
            Tag tag = Tag.Context(0x04, ASN1.PC.Constructed); 
        
            // выполнить команду
            Response response = channel.SendCommand(SecureType.None, 
                null, INS.ManageSecurityEnvironment, 0x08, 0xA4, new byte[0], -1
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response);
        
            // раскодировать объект
            return new BER.CRT.AT(tag, tagScheme, response.Data); 
        }
        // установить параметры алгоритма
        public void SetAuthenticationParameters(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, IEnumerable<DataObject> objs) 
        {
            // указать схему кодирования
            TagScheme tagScheme = channel.Environment.TagScheme; 
        
            // закодировать объекты
            byte[] encoded = DataObject.Encode(tagScheme, objs); 
        
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.ManageSecurityEnvironment, 0x01, 0xA4, encoded, 0
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response);
        }
        // получить параметры алгоритма
        public BER.CRT.HT GetHashParameters(LogicalChannel channel) 
        {
            // указать схему кодирования
            TagScheme tagScheme = channel.Environment.TagScheme; 
        
            // указать тип объекта
            Tag tag = Tag.Context(0x0A, ASN1.PC.Constructed); 
            
            // выполнить команду
            Response response = channel.SendCommand(SecureType.None, 
                null, INS.ManageSecurityEnvironment, 0x08, 0xAA, new byte[0], -1
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response);
        
            // раскодировать объект
            return new BER.CRT.HT(tag, tagScheme, response.Data); 
        }
        // установить параметры алгоритма
        public void SetHashParameters(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, IEnumerable<DataObject> objs) 
        {
            // указать схему кодирования
            TagScheme tagScheme = channel.Environment.TagScheme; 
        
            // закодировать объекты
            byte[] encoded = DataObject.Encode(tagScheme, objs); 
        
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.ManageSecurityEnvironment, 0x01, 0xAA, encoded, 0
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response);
        }
        // получить параметры алгоритма
        public BER.CRT.CCT GetMacParameters(LogicalChannel channel) 
        {
            // указать схему кодирования
            TagScheme tagScheme = channel.Environment.TagScheme; 
        
            // указать тип объекта
            Tag tag = Tag.Context(0x14, ASN1.PC.Constructed); 
            
            // выполнить команду
            Response response = channel.SendCommand(SecureType.None, 
                null, INS.ManageSecurityEnvironment, 0x08, 0xB4, new byte[0], -1
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response);
        
            // раскодировать объект
            return new BER.CRT.CCT(tag, tagScheme, response.Data); 
        }
        // установить параметры алгоритма
        public void SetMacParameters(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, IEnumerable<DataObject> objs) 
        {
            // указать схему кодирования
            TagScheme tagScheme = channel.Environment.TagScheme; 
        
            // закодировать объекты
            byte[] encoded = DataObject.Encode(tagScheme, objs); 
        
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.ManageSecurityEnvironment, 0x01, 0xB4, encoded, 0
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response);
        }
        // получить параметры алгоритма
        public BER.CRT.CT GetCipherParameters(LogicalChannel channel) 
        {
            // указать схему кодирования
            TagScheme tagScheme = channel.Environment.TagScheme; 
        
            // указать тип объекта
            Tag tag = Tag.Context(0x18, ASN1.PC.Constructed); 
            
            // выполнить команду
            Response response = channel.SendCommand(SecureType.None, 
                null, INS.ManageSecurityEnvironment, 0x08, 0xB8, new byte[0], -1
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response);
        
            // раскодировать объект
            return new BER.CRT.CT(tag, tagScheme, response.Data); 
        }
        // установить параметры алгоритма
        public void SetCipherParameters(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, IEnumerable<DataObject> objs) 
        {
            // указать схему кодирования
            TagScheme tagScheme = channel.Environment.TagScheme; 
        
            // закодировать объекты
            byte[] encoded = DataObject.Encode(tagScheme, objs); 
        
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.ManageSecurityEnvironment, 0x01, 0xB8, encoded, 0
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response);
        }
        // получить параметры алгоритма
        public BER.CRT.DST GetSignParameters(LogicalChannel channel) 
        {
            // указать схему кодирования
            TagScheme tagScheme = channel.Environment.TagScheme; 
        
            // указать тип объекта
            Tag tag = Tag.Context(0x16, ASN1.PC.Constructed); 
            
            // выполнить команду
            Response response = channel.SendCommand(SecureType.None, 
                null, INS.ManageSecurityEnvironment, 0x08, 0xB6, new byte[0], -1
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response);
        
            // раскодировать объект
            return new BER.CRT.DST(tag, tagScheme, response.Data); 
        }
        // установить параметры алгоритма
        public void SetSignParameters(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, IEnumerable<DataObject> objs) 
        {
            // указать схему кодирования
            TagScheme tagScheme = channel.Environment.TagScheme; 
        
            // закодировать объекты
            byte[] encoded = DataObject.Encode(tagScheme, objs); 
        
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.ManageSecurityEnvironment, 0x01, 0xB6, encoded, 0
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response);
        }
        // получить параметры алгоритма
        public BER.CRT.KAT GetKeyAgreementParameters(LogicalChannel channel) 
        {
            // указать схему кодирования
            TagScheme tagScheme = channel.Environment.TagScheme; 
        
            // указать тип объекта
            Tag tag = Tag.Context(0x06, ASN1.PC.Constructed); 
            
            // выполнить команду
            Response response = channel.SendCommand(SecureType.None, 
                null, INS.ManageSecurityEnvironment, 0x08, 0xA6, new byte[0], -1
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response);
        
            // раскодировать объект
            return new BER.CRT.KAT(tag, tagScheme, response.Data); 
        }
        // установить параметры алгоритма
        public void SetKeyAgreementParameters(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, IEnumerable<DataObject> objs) 
        {
            // указать схему кодирования
            TagScheme tagScheme = channel.Environment.TagScheme; 
        
            // закодировать объекты
            byte[] encoded = DataObject.Encode(tagScheme, objs); 
        
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.ManageSecurityEnvironment, 0x01, 0xA6, encoded, 0
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response);
        }
    }
}
