using System;
using System.Collections.Generic;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////////
    // Реализация криптографических операций через карту
    ///////////////////////////////////////////////////////////////////////////////
    public class SecureModule : SecureClient
    {
        // используемый канал и криптографическое окружение
        private LogicalChannel channel; private SecurityEnvironment environment;
    
        // конструктор
        public SecureModule(LogicalChannel channel)
        { 
            // сохранить переданные параметры
            this.channel = channel; environment = SecurityEnvironment.Current; 
        }
        // получить параметры алгоритма
        public BER.CRT.AT GetAuthenticationParameters() 
        {
            // получить параметры алгоритма
            return environment.GetAuthenticationParameters(channel); 
        }
        // установить параметры алгоритма
        public void SetAuthenticationParameters(IEnumerable<DataObject> objs) 
        {
            // установить параметры алгоритма
            environment.SetAuthenticationParameters(channel, SecureType.None, null, objs);
        }
        // получить параметры алгоритма
        public BER.CRT.HT GetHashParameters() 
        {
            // получить параметры алгоритма
            return environment.GetHashParameters(channel); 
        }
        // установить параметры алгоритма
        public void SetHashParameters(IEnumerable<DataObject> objs) 
        {
            // установить параметры алгоритма
            environment.SetHashParameters(channel, SecureType.None, null, objs);
        }
        // получить параметры алгоритма
        public BER.CRT.CCT GetMacParameters() 
        {
            // получить параметры алгоритма
            return environment.GetMacParameters(channel); 
        }
        // установить параметры алгоритма
        public void SetMacParameters(IEnumerable<DataObject> objs) 
        {
            // установить параметры алгоритма
            environment.SetMacParameters(channel, SecureType.None, null, objs);
        }
        // получить параметры алгоритма
        public BER.CRT.CT GetCipherParameters() 
        {
            // получить параметры алгоритма
            return environment.GetCipherParameters(channel); 
        }
        // установить параметры алгоритма
        public void SetCipherParameters(IEnumerable<DataObject> objs) 
        {
            // установить параметры алгоритма
            environment.SetCipherParameters(channel, SecureType.None, null, objs);
        }
        // получить параметры алгоритма
        public BER.CRT.DST GetSignParameters() 
        {
            // получить параметры алгоритма
            return environment.GetSignParameters(channel); 
        }
        // установить параметры алгоритма
        public void SetSignParameters(IEnumerable<DataObject> objs) 
        {
            // установить параметры алгоритма
            environment.SetSignParameters(channel, SecureType.None, null, objs);
        }
        // получить параметры алгоритма
        public BER.CRT.KAT GetKeyAgreementParameters() 
        {
            // получить параметры алгоритма
            return environment.GetKeyAgreementParameters(channel); 
        }
        // установить параметры алгоритма
        public void SetKeyAgreementParameters(IEnumerable<DataObject> objs) 
        {
            // установить параметры алгоритма
            environment.SetKeyAgreementParameters(channel, SecureType.None, null, objs);
        }
        // размер блока при вычислении имитовставки и подписи
        public virtual int ChecksumBlockSize { get { return 1; }}
        public virtual int SignBlockSize     { get { return 1; }} 
    
        // объединить данные
        private byte[] Concat(byte[][] data, int blockSize)
        {
            // указать начальные условия
            byte[] buffer = (data.Length > 0) ? data[0] : new byte[0]; 
                
            // для всех частей данных
            for (int i = 1; i < data.Length; i++)
            {
                // сохранить размер буфера
                int position = buffer.Length; 
            
                // определить новый размер буфера
                int length = (position + blockSize) / blockSize * blockSize; 
            
                // изменить размер буфера
                Array.Resize(ref buffer, length); buffer[position] = 0x80;
            
                // скопировать часть данных
                Array.Copy(data[i], 0, buffer, length, data[i].Length);
            }
            return buffer; 
        }
        // захэшировать данные
        public override byte[] Hash(BER.CRT.HT parameters, byte[] data) 
        {
            // при отсутствии дополнительных параметров
            if (parameters == null)
            {
                // захэшировать данные
                Response response = channel.SendCommand(
                    INS.PerformSecurityOperation, 0x90, 0x80, data, -1
                ); 
                // проверить отсутствие ошибок
                ResponseException.Check(response); return response.Data; 
            }
            // заблокировать карту
            using (CardLock cardLock = new CardLock(channel.Session))
            {
                // получить параметры алгоритма
                BER.CRT.HT oldParameters = GetHashParameters(); 
                
                // переустановить параметры алгоритма
                SetHashParameters(parameters); 
                try { 
                    // захэшировать данные
                    return Hash(null, data); 
                }
                // восстановить параметры алгоритма
                finally { SetHashParameters(oldParameters); }
            }
        }
        // вычислить контрольную сумму
        public override byte[] Checksum(BER.CRT.CCT parameters, byte[][] data) 
        {
            // при отсутствии дополнительных параметров
            if (parameters == null)
            {
                // объединить данные
                byte[] buffer = Concat(data, ChecksumBlockSize); 

                // вычислить контрольную сумму
                Response response = channel.SendCommand(
                    INS.PerformSecurityOperation, 0x8E, 0x80, buffer, -1
                ); 
                // проверить отсутствие ошибок
                ResponseException.Check(response); return response.Data; 
            }
            // заблокировать карту
            using (CardLock cardLock = new CardLock(channel.Session))
            {
                // получить параметры алгоритма
                BER.CRT.CCT oldParameters = GetMacParameters(); 
                
                // переустановить параметры алгоритма
                SetMacParameters(parameters); 
                try { 
                    // вычислить контрольную сумму
                    return Checksum(null, data); 
                }
                // восстановить параметры алгоритма
                finally { SetMacParameters(oldParameters); }
            }
        }
        // зашифровать данные
        public override byte[] Encrypt(BER.CRT.CT parameters, byte[] data, SecureType secureType) 
        {
            // при отсутствии дополнительных параметров
            if (parameters == null) { byte outputType = 0x86; 
        
                // указать код команды
                if ((secureType & SecureType.BERTLV) != 0) { outputType = 0x84; 
            
                    // указать код команды
                    if ((secureType & SecureType.BERTLVSM) == SecureType.BERTLVSM) outputType = 0x82; 
                }
                // зашифровать данные
                Response response = channel.SendCommand(
                    INS.PerformSecurityOperation, outputType, 0x80, data, -1
                ); 
                // проверить отсутствие ошибок
                ResponseException.Check(response); return response.Data; 
            }
            // заблокировать карту
            using (CardLock cardLock = new CardLock(channel.Session))
            {
                // получить параметры алгоритма
                BER.CRT.CT oldParameters = GetCipherParameters(); 
                
                // переустановить параметры алгоритма
                SetCipherParameters(parameters); 
                try { 
                    // зашифровать данные
                    return Encrypt(null, data, secureType); 
                }
                // восстановить параметры алгоритма
                finally { SetCipherParameters(oldParameters); }
            }
        }
        // расшифровать данные
        public override byte[] Decrypt(BER.CRT.CT parameters, byte[] data, SecureType secureType) 
        {
            // при отсутствии дополнительных параметров
            if (parameters == null) { byte inputType = 0x86; 
        
                // указать код команды
                if ((secureType & SecureType.BERTLV) != 0) { inputType = 0x84; 
            
                    // указать код команды
                    if ((secureType & SecureType.BERTLVSM) == SecureType.BERTLVSM) inputType = 0x82; 
                } 
                // расшифровать данные
                Response response = channel.SendCommand(
                    INS.PerformSecurityOperation, 0x80, inputType, data, -1
                ); 
                // проверить отсутствие ошибок
                ResponseException.Check(response); return response.Data; 
            }
            // заблокировать карту
            using (CardLock cardLock = new CardLock(channel.Session))
            {
                // получить параметры алгоритма
                BER.CRT.CT oldParameters = GetCipherParameters(); 
                
                // переустановить параметры алгоритма
                SetCipherParameters(parameters); 
                try { 
                    // расшифровать данные
                    return Decrypt(null, data, secureType); 
                }
                // восстановить параметры алгоритма
                finally { SetCipherParameters(oldParameters); }
            }
        }
        // подписать данные
        public override byte[] Sign(BER.CRT.DST parameters, byte[][] data) 
        {
            // при отсутствии дополнительных параметров
            if (parameters == null)
            {
                // объединить данные
                byte[] buffer = Concat(data, SignBlockSize); 

                // подписать данные
                Response response = channel.SendCommand(
                    INS.PerformSecurityOperation, 0x9E, 0x9A, buffer, -1
                ); 
                // проверить отсутствие ошибок
                ResponseException.Check(response); return response.Data; 
            }
            // заблокировать карту
            using (CardLock cardLock = new CardLock(channel.Session))
            {
                // получить параметры алгоритма
                BER.CRT.DST oldParameters = GetSignParameters(); 
                
                // переустановить параметры алгоритма
                SetSignParameters(parameters); 
                try { 
                    // подписать данные
                    return Sign(null, data); 
                }
                // восстановить параметры алгоритма
                finally { SetSignParameters(oldParameters); }
            }
        }
        // проверить подпись данных
        public override void Verify(BER.CRT.DST parameters, byte[][] data, byte[] sign) 
        {
            // при отсутствии дополнительных параметров
            if (parameters == null)
            {
                // объединить данные
                byte[] buffer = Concat(data, SignBlockSize); 

                // закодировать данные
                ASN1.IEncodable encodedData = ASN1.Encodable.Encode(
                    ASN1.Tag.Context(0x1A), ASN1.PC.Primitive, buffer
                ); 
                // закодировать подпись
                ASN1.IEncodable encodedSign = ASN1.Encodable.Encode(
                    ASN1.Tag.Context(0x1E), ASN1.PC.Primitive, sign
                ); 
                // объединить данные и подпись
                byte[] encoded = Arrays.Concat(encodedData.Encoded, encodedSign.Encoded); 
            
                // подписать данные
                Response response = channel.SendCommand(
                    INS.PerformSecurityOperation, 0x00, 0xA8, encoded, 0
                ); 
                // проверить отсутствие ошибок
                ResponseException.Check(response); return; 
            }
            // заблокировать карту
            using (CardLock cardLock = new CardLock(channel.Session))
            {
                // получить параметры алгоритма
                BER.CRT.DST oldParameters = GetSignParameters(); 
                
                // переустановить параметры алгоритма
                SetSignParameters(parameters); 
                try { 
                    // проверить подпись данных
                    Verify(null, data, sign);  
                }
                // восстановить параметры алгоритма
                finally { SetSignParameters(oldParameters); }
            }
        }
    }
}
