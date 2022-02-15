package aladdin.capi;
import aladdin.*;
import java.security.*;
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Симметричный алгоритм шифрования с выработкой имитовставки
///////////////////////////////////////////////////////////////////////////
public class CipherMac extends Cipher
{
    // алгоритм шифрования и алгоритм вычисления имитовставки
    private final Cipher cipher; private final Mac macAlgorithm;
        
    // конструктор
    public CipherMac(Cipher cipher, Mac macAlgorithm)
    {
        // сохранить переданные параметры
        this.cipher = RefObject.addRef(cipher); 

        // сохранить переданные параметры
        this.macAlgorithm = RefObject.addRef(macAlgorithm); 
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException
    { 
        // освободить выделенные ресурсы
        RefObject.release(macAlgorithm); 

        // освободить выделенные ресурсы
        RefObject.release(cipher); super.onClose();         
    } 
    // алгоритм зашифрования данных
	@Override public Transform createEncryption(ISecretKey key, PaddingMode padding) 
        throws IOException, InvalidKeyException
	{
        // создать ключи для алгоритмов
        ISecretKey[] keys = createKeys(key); 
        try {
            // создать преобразование зашифрования
            try (Transform encryption = cipher.createEncryption(keys[0], padding)) 
            {
                // создать алгоритм вычисления имитовставки
                try (Hash hashAlgorithm = macAlgorithm.convertToHash(keys[1]))
                {
                    // вернуть преобразование зашифрования
                    return new Encryption(encryption, hashAlgorithm); 
                }
            }
        }
        // освободить выделенные ресурсы
        finally { keys[0].close(); keys[1].close(); }
	}
	// алгоритм расшифрования данных
	@Override public Transform createDecryption(ISecretKey key, PaddingMode padding) 
        throws IOException, InvalidKeyException 
	{
        // создать ключи для алгоритмов
        ISecretKey[] keys = createKeys(key); 
        try {
            // создать преобразование расшифрования
            try (Transform decryption = cipher.createDecryption(keys[0], padding)) 
            {
                // создать алгоритм вычисления имитовставки
                try (Hash hashAlgorithm = macAlgorithm.convertToHash(keys[1]))
                {
                    // вернуть преобразование расcшифрования
                    return new Decryption(decryption, hashAlgorithm); 
                }
            }
        }
        // освободить выделенные ресурсы
        finally { keys[0].close(); keys[1].close(); }
	}
    // создать ключи для алгоритмов
	protected ISecretKey[] createKeys(ISecretKey key) 
        throws IOException, InvalidKeyException
    {
        // создать ключи для алгоритмов
        return new ISecretKey[] { RefObject.addRef(key), RefObject.addRef(key) }; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Зашифрование данных и выработки имитовставки
    ///////////////////////////////////////////////////////////////////////////
    public class Encryption extends Transform
    {
        // преобразование зашифрования и алгоритм вычисления имитовставки
        private final Transform encryption; private final Hash hashAlgorithm;
        
        // конструктор
        public Encryption(Transform encryption, Hash hashAlgorithm)
        {
            // проверить корректность размера блока
            if ((encryption.blockSize() % hashAlgorithm.blockSize()) != 0)
            {
                // при ошибке выбросить исключение
                throw new IllegalStateException(); 
            }
            // сохранить переданные параметры
            this.encryption = RefObject.addRef(encryption); 

            // сохранить переданные параметры
            this.hashAlgorithm = RefObject.addRef(hashAlgorithm); 
        }
        // освободить выделенные ресурсы
        @Override protected void onClose() throws IOException
        { 
            // освободить выделенные ресурсы
            RefObject.release(hashAlgorithm); 

            // освободить выделенные ресурсы
            RefObject.release(encryption); super.onClose();         
        } 
        // размер блока
        @Override public int blockSize() { return encryption.blockSize(); } 
    
        // преобразовать данные
        @Override public int transformData(byte[] data, 
            int dataOff, int dataLen, byte[] buf, int bufOff) throws IOException
        {
            // определить число блоков данных
            int blockSize = blockSize(); int cb = dataLen / blockSize * blockSize; 

             // преобразовать данные
            init(); int total = update(data, dataOff, cb, buf, bufOff); 

            // преобразовать данные
            return total + finish(data, dataOff + cb, dataLen - cb, buf, bufOff + total);
        }
        // преобразовать данные
        @Override public byte[] transformData(byte[] data, int dataOff, int dataLen) throws IOException
        {
            // определить размер блока и имитовставки
            int blockSize = blockSize(); int macSize = hashAlgorithm.blockSize(); 
            
            // выделить буфер для результата
            byte[] buffer = new byte[(dataLen / blockSize + 1) * blockSize + macSize];

            // определить число блоков данных
            int cb = dataLen / blockSize * blockSize; init(); 

            // преобразовать данные
            int total = update(data, dataOff, cb, buffer, 0); 

            // преобразовать данные
            total += finish(data, dataOff + cb, dataLen - cb, buffer, total); 

            // переразместить буфер
            return (total < buffer.length) ? Arrays.copyOf(buffer, total) : buffer; 
        }
        // инициализировать алгоритм
        @Override public void init() throws IOException 
        {
            // инициализировать алгоритм
            encryption.init(); hashAlgorithm.init();
        } 
        // преобразовать данные
        @Override public int update(byte[] data, int dataOff, 
            int dataLen, byte[] buf, int bufOff) throws IOException
        {
            // захэшировать данные
            hashAlgorithm.update(data, dataOff, dataLen);
            
            // зашифровать данные
            return encryption.update(data, dataOff, dataLen, buf, bufOff); 
        }
        // завершить преобразование
        @Override public int finish(byte[] data, int dataOff, 
            int dataLen, byte[] buf, int bufOff) throws IOException
        {
            // определить размер имитовставки
            int macSize = hashAlgorithm.hashSize(); 
            
            // захэшировать данные
            hashAlgorithm.update(data, dataOff, dataLen);
            
            // зашифровать данные
            int cb = encryption.finish(data, dataOff, dataLen, buf, bufOff); 
            
            // проверить размер буфера
            if (buf.length < bufOff + cb + macSize) throw new IOException(); 
            
            // вычислить имитовставку
            return cb + hashAlgorithm.finish(buf, bufOff + cb); 
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Расшифрование данных и проверка имитовставки
    ///////////////////////////////////////////////////////////////////////////
    public class Decryption extends Transform
    {
        // преобразование расшифрования и алгоритм вычисления имитовставки
        private final Transform decryption; private final Hash hashAlgorithm;
        
        // последний блок и имитовставка
        private byte[] last; 
        
        // конструктор
        public Decryption(Transform decryption, Hash hashAlgorithm)
        {
            // проверить корректность размера блока
            if ((decryption.blockSize() % hashAlgorithm.blockSize()) != 0)
            {
                // при ошибке выбросить исключение
                throw new IllegalStateException(); 
            }
            // сохранить переданные параметры
            this.decryption = RefObject.addRef(decryption); last = null; 

            // сохранить переданные параметры
            this.hashAlgorithm = RefObject.addRef(hashAlgorithm); 
        }
        // освободить выделенные ресурсы
        @Override protected void onClose() throws IOException
        { 
            // освободить выделенные ресурсы
            RefObject.release(hashAlgorithm); 

            // освободить выделенные ресурсы
            RefObject.release(decryption); super.onClose();         
        } 
        // размер блока
        @Override public int blockSize() { return decryption.blockSize(); } 
        
        // преобразовать данные
        @Override public int transformData(byte[] data, 
            int dataOff, int dataLen, byte[] buf, int bufOff) throws IOException
        {
            // определить размер блока и имитовставки
            int blockSize = blockSize(); int macSize = hashAlgorithm.hashSize(); 
            
            // проверить размер данных
            if (dataLen < macSize) throw new IOException(); 
            
            // определить число блоков данных
            int cb = dataLen / blockSize * blockSize; init(); 

             // преобразовать данные
            int total = update(data, dataOff, cb, buf, bufOff); 

            // преобразовать данные
            return total + finish(data, dataOff + cb, dataLen - cb, buf, bufOff + total);
        }
        // преобразовать данные
        @Override public byte[] transformData(byte[] data, int dataOff, int dataLen) throws IOException
        {
            // определить размер блока и имитовставки
            int blockSize = blockSize(); int macSize = hashAlgorithm.hashSize(); 
            
            // проверить размер данных
            if (dataLen < macSize) throw new IOException(); 
            
            // выделить буфер для результата
            byte[] buffer = new byte[dataLen - macSize];

            // определить число блоков данных
            int cb = dataLen / blockSize * blockSize; init(); 

            // преобразовать данные
            int total = update(data, dataOff, cb, buffer, 0); 

            // преобразовать данные
            total += finish(data, dataOff + cb, dataLen - cb, buffer, total); 

            // переразместить буфер
            return (total < buffer.length) ? Arrays.copyOf(buffer, total) : buffer; 
        }
        // инициализировать алгоритм
        @Override public void init() throws IOException 
        {
            // инициализировать алгоритм
            decryption.init(); hashAlgorithm.init(); last = new byte[0]; 
        } 
        // преобразовать данные
        @Override public int update(byte[] data, int dataOff, 
            int dataLen, byte[] buf, int bufOff) throws IOException
        {
            // определить размер блока и имитовставки
            int blockSize = blockSize(); int macSize = hashAlgorithm.hashSize(); 
            
            // проверить необходимость действий
            if (dataLen == 0) return 0; if ((dataLen % blockSize) != 0) throw new IOException(); 
            
            // определить размер сохраняемых данных
            int lastSize = (macSize + blockSize - 1) / blockSize * blockSize; 
            
            // при недостаточности данных
            if (last.length + dataLen < lastSize)
            {
                // переразместить буфер
                int cb = last.length; last = Arrays.copyOf(last, last.length + dataLen); 
                
                // сохранить данные
                System.arraycopy(data, dataOff, last, cb, dataLen); return 0; 
            }
            // при недостаточности данных
            if (last.length < lastSize)
            {
                // переразместить буфер
                int cb = last.length; last = Arrays.copyOf(last, lastSize); 
                
                // сохранить данные
                System.arraycopy(data, dataOff, last, cb, lastSize - cb); 
                
                // скорректировать смещение
                dataOff += lastSize - cb; dataLen -= lastSize - cb; if (dataLen == 0) return 0; 
            }
            if (lastSize >= dataLen)
            {
                // расшифровать данные
                decryption.update(last, 0, dataLen, buf, bufOff);
                
                // захэшировать данные
                hashAlgorithm.update(buf, bufOff, dataLen);
                
                // сместить данные
                System.arraycopy(last, dataLen, last, 0, lastSize - dataLen);
                
                // сохранить данные
                System.arraycopy(data, dataOff, last, lastSize - dataLen, dataLen); 
            }
            else {
                // расшифровать данные
                decryption.update(last, 0, lastSize, buf, bufOff); 
                
                // захэшировать данные
                hashAlgorithm.update(buf, bufOff, lastSize); bufOff += lastSize; 
                
                // расшифровать данные
                decryption.update(data, dataOff, dataLen - lastSize, buf, bufOff); 
                
                // захэшировать данные
                hashAlgorithm.update(buf, bufOff, dataLen - lastSize); 
                
                // скорректировать смещение
                dataOff += dataLen - lastSize; bufOff += dataLen - lastSize; 
                
                // сохранить данные
                System.arraycopy(data, dataOff, last, 0, lastSize); 
            }
            return dataLen; 
        }
        // завершить преобразование
        @Override public int finish(byte[] data, int dataOff, 
            int dataLen, byte[] buf, int bufOff) throws IOException
        {
            // определить размер блока и имитовставки
            int blockSize = blockSize(); int macSize = hashAlgorithm.hashSize(); 
            
            // определить число полных блоков
            int cbBlocks = dataLen / blockSize * blockSize; int cb = 0; 
            
            // обработать полные блоки
            if (cbBlocks > 0) { cb = update(data, dataOff, cbBlocks, buf, bufOff); 
            
                // скорректировать смещение
                dataOff += cbBlocks; dataLen -= cbBlocks; bufOff += cb; 
            }
            // проверить размер данных
            if (last.length + dataLen < macSize) throw new IOException(); 
            
            // выделить память для имитовставки
            byte[] check = new byte[macSize]; if (dataLen <= macSize)
            {
                // скопировать часть имитовставки
                System.arraycopy(last, last.length - (macSize - dataLen), check, 0, macSize - dataLen); 

                // скопировать часть имитовставки
                System.arraycopy(data, dataOff, check, macSize - dataLen, dataLen); 
                
                // расшифровать последний блок
                int bytes = decryption.finish(last, 0, last.length - (macSize - dataLen), buf, bufOff); 
                
                // захэшировать данные
                hashAlgorithm.update(buf, bufOff, bytes); cb += bytes; 
            }
            // выделить память под последний блок
            else { last = Arrays.copyOf(last, last.length + (dataLen - macSize)); 
            
                // скопировать часть последнего блока
                System.arraycopy(data, dataOff, last, last.length - (dataLen - macSize), dataLen - macSize); 
                
                // скопировать имитовставку
                System.arraycopy(data, dataOff + (dataLen - macSize), check, 0, macSize); 

                // расшифровать последний блок
                int bytes = decryption.finish(last, 0, last.length, buf, bufOff); 
                
                // захэшировать данные
                hashAlgorithm.update(buf, bufOff, bytes); cb += bytes; 
            }
            // вычислить имитовставку
            byte[] mac = new byte[macSize]; hashAlgorithm.finish(mac, 0); 
            
            // проверить совпадение имитовставки
            if (!Arrays.equals(mac, check)) throw new IOException(); return cb; 
        }
    }
}
