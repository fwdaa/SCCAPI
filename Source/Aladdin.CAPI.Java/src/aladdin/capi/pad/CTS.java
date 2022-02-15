package aladdin.capi.pad;
import aladdin.*; 
import aladdin.capi.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Дополнение CTS
///////////////////////////////////////////////////////////////////////////////
public class CTS extends BlockPadding
{ 
    // идентификатор режима
    @Override public PaddingMode mode() { return PaddingMode.CTS; } 
    
    // алгоритм зашифрования данных
	@Override public Transform createEncryption(Transform encryption, CipherMode mode)
    {
        // вызвать базовую функцию
        Transform transform = super.createEncryption(encryption, mode); 

	    // проверить совпадение режима
        if (transform != null) return transform; 

        // алгоритм зашифрования данных
        if (mode instanceof CipherMode.ECB) return new EncryptionECB(encryption); 
        if (mode instanceof CipherMode.CBC) return new EncryptionCBC(encryption); 

        // некорректный режим
        throw new IllegalStateException();
    }
	// алгоритм расшифрования данных
	@Override public Transform createDecryption(Transform decryption, CipherMode mode)
    {
        // вызвать базовую функцию
        Transform transform = super.createDecryption(decryption, mode); 

	    // проверить совпадение режима
        if (transform != null) return transform; 

	    // алгоритм расшифрования данных
        if (mode instanceof CipherMode.ECB) return new DecryptionECB(decryption); 
        if (mode instanceof CipherMode.CBC) 
        {
            // преобразовать тип параметров
            CipherMode.CBC parameters = (CipherMode.CBC)mode; 

            // вернуть преобразование расшифрования
            return new DecryptionCBC(decryption, parameters.iv()); 
        }
        // некорректный режим
        throw new IllegalStateException();
    }
    ///////////////////////////////////////////////////////////////////////////////
    // Режим зашифрования ECB с дополнением CTS
    ///////////////////////////////////////////////////////////////////////////////
    public static class EncryptionECB extends Transform
    {
        private final Transform encryption;   // режим зашифрования данных
        private byte[]          lastBlock;    // последний зашифрованный блок данных

        // конструктор
        public EncryptionECB(Transform encryption) 
        { 
            // сохранить переданные параметры
            this.encryption = RefObject.addRef(encryption); 
        }
        // освободить выделенные ресурсы
        @Override protected void onClose() throws IOException  
        { 
            // освободить выделенные ресурсы
            RefObject.release(encryption); super.onClose(); 
        } 
        // размер блока алгоритма
        @Override public int blockSize() { return encryption.blockSize(); }

        // режим дополнения
        @Override public PaddingMode padding() { return PaddingMode.CTS; }

        // инициализировать алгоритм
        @Override public void init() throws IOException { encryption.init(); lastBlock = null; } 

        @Override public int update(byte[] data, int dataOff, 
            int dataLen, byte[] buf, int bufOff) throws IOException
        {
            // проверить необходимость действий
            int blockSize = blockSize(); if (dataLen == 0) return 0; 

            // проверить корректность данных
            if ((dataLen % blockSize) != 0) throw new IllegalArgumentException(); 

            // определить размер полных блоков кроме последнего
            int cbBlocks = ((dataLen - 1) / blockSize) * blockSize;

            // при наличии последнего блока
            if (lastBlock != null) 
            {
                // скопировать зашифрованный последний блок
                System.arraycopy(lastBlock, 0, buf, bufOff, blockSize); bufOff += blockSize;  

                // зашифровать полные блоки кроме последнего
                encryption.update(data, dataOff, cbBlocks, buf, bufOff);

                // сохранить последний блок
                System.arraycopy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); 

                // зашифровать последний блок
                encryption.update(lastBlock, 0, blockSize, lastBlock, 0); return dataLen; 
            }
            else {
                // зашифровать полные блоки кроме последнего
                encryption.update(data, dataOff, cbBlocks, buf, bufOff);

                // выделить память для последнего блока
                lastBlock = new byte[blockSize]; 

                // сохранить последний блок
                System.arraycopy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); 

                // зашифровать последний блок
                encryption.update(lastBlock, 0, blockSize, lastBlock, 0); return cbBlocks; 
            }
        }
        @Override public int finish(byte[] data, int dataOff, 
            int dataLen, byte[] buf, int bufOff) throws IOException
        {
            // в режиме совместимости
            int blockSize = blockSize(); if (/*legacy &&*/(dataLen % blockSize) == 0)
            {
                // скопировать зашифрованный последний блок
                int cb = 0; if (lastBlock != null) System.arraycopy(lastBlock, 0, buf, bufOff, cb = blockSize);

                // обработать последние данные
                if (dataLen != 0) cb += encryption.finish(data, dataOff, dataLen, buf, bufOff + cb); return cb; 
            }
            else { 
                // при наличии последнего блока
                if (lastBlock != null) 
                {
                    // проверить корректность данных
                    if (dataLen == 0) throw new IllegalArgumentException(); 
                }
                else {
                    // проверить достаточность данных
                    if (dataLen <= blockSize) throw new IllegalArgumentException();
                }
                // определить размер полных блоков кроме последнего
                int cbBlocks = ((dataLen - 1) / blockSize) * blockSize;

                // обработать все блоки, кроме двух последних
                int cb = update(data, dataOff, cbBlocks, buf, bufOff); 

                // перейти на последний блок
                dataOff += cbBlocks; dataLen -= cbBlocks; bufOff += cb; 

                // скопировать часть зашифрованных данных в последний блок
                System.arraycopy(lastBlock, 0, buf, bufOff + blockSize, dataLen);

                // скопировать последний блок для зашифрования
                System.arraycopy(data, dataOff, lastBlock, 0, dataLen); 

                // зашифровать блок в предпоследний блок
                encryption.update(lastBlock, 0, blockSize, buf, bufOff); 

                // вернуть размер данных
                return cb + blockSize + dataLen; 
            }
        }
    }
    ///////////////////////////////////////////////////////////////////////////////
    // Режим расшифрования ECB с дополнением CTS
    ///////////////////////////////////////////////////////////////////////////////
    public static class DecryptionECB extends Transform
    {
        private final Transform decryption;	// режим расшифрования данных
        private byte[]          lastBlock;  // последний расшифрованный блок данных

        // конструктор
        public DecryptionECB(Transform decryption) 
        { 
            // сохранить переданные параметры
            this.decryption = RefObject.addRef(decryption); 
        }
        // освободить выделенные ресурсы
        @Override protected void onClose() throws IOException  
        { 
            // освободить выделенные ресурсы
            RefObject.release(decryption); super.onClose(); 
        } 
        // размер блока алгоритма
        @Override public int blockSize() { return decryption.blockSize(); }

        // режим дополнения
        @Override public PaddingMode padding() { return PaddingMode.CTS; }

        // инициализировать алгоритм
        @Override public void init() throws IOException { decryption.init(); lastBlock = null; } 

        @Override public int update(byte[] data, int dataOff, 
            int dataLen, byte[] buf, int bufOff) throws IOException
        {
            // проверить необходимость действий
            int blockSize = blockSize(); if (dataLen == 0) return 0; 

            // проверить корректность данных
            if ((dataLen % blockSize) != 0) throw new IllegalArgumentException(); 

            // определить размер полных блоков кроме последнего
            int cbBlocks = ((dataLen - 1) / blockSize) * blockSize;

            // при наличии последнего блока
            if (lastBlock != null) 
            {
                // скопировать расшифрованный последний блок
                System.arraycopy(lastBlock, 0, buf, bufOff, blockSize); bufOff += blockSize;  

                // расшифровать полные блоки кроме последнего
                decryption.update(data, dataOff, cbBlocks, buf, bufOff);

                // сохранить последний блок
                System.arraycopy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); 

                // расшифровать последний блок
                decryption.update(lastBlock, 0, blockSize, lastBlock, 0); return dataLen; 
            }
            else {
                // расшифровать полные блоки кроме последнего
                decryption.update(data, dataOff, cbBlocks, buf, bufOff);

                // выделить память для последнего блока
                lastBlock = new byte[blockSize]; 

                // сохранить последний блок
                System.arraycopy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); 

                // расшифровать последний блок
                decryption.update(lastBlock, 0, blockSize, lastBlock, 0); return cbBlocks; 
            }
        }
        @Override public int finish(byte[] data, int dataOff, 
            int dataLen, byte[] buf, int bufOff) throws IOException
        {
            // в режиме совместимости
            int blockSize = blockSize(); if (/*legacy &&*/(dataLen % blockSize) == 0)
            {
                // скопировать расшифрованный последний блок
                int cb = 0; if (lastBlock != null) System.arraycopy(lastBlock, 0, buf, bufOff, cb = blockSize);

                // обработать последние данные
                if (dataLen != 0) cb += decryption.finish(data, dataOff, dataLen, buf, bufOff + cb); return cb; 
            }
            else { 
                // при наличии последнего блока
                if (lastBlock != null) 
                {
                    // проверить корректность данных
                    if (dataLen == 0) throw new IOException(); 
                }
                // проверить корректность данных
                else if (dataLen <= blockSize) throw new IOException(); 

                // определить размер полных блоков кроме последнего
                int cbBlocks = ((dataLen - 1) / blockSize) * blockSize;

                // обработать все блоки, кроме двух последних
                int cb = update(data, dataOff, cbBlocks, buf, bufOff); 

                // перейти на последний блок
                dataOff += cbBlocks; dataLen -= cbBlocks; bufOff += cb; 

                // скопировать часть расшифрованных данных в последний блок
                System.arraycopy(lastBlock, 0, buf, bufOff + blockSize, dataLen);

                // скопировать последний блок для расшифрования
                System.arraycopy(data, dataOff, lastBlock, 0, dataLen);

                // расшифровать блок в предпоследний блок
                decryption.update(lastBlock, 0, blockSize, buf, bufOff); 

                // вернуть размер данных
                return cb + blockSize + dataLen; 
            }
        }
    }
    ///////////////////////////////////////////////////////////////////////////////
    // Режим зашифрования CBC с дополнением CTS
    ///////////////////////////////////////////////////////////////////////////////
    public static class EncryptionCBC extends Transform
    {
        private final Transform encryption;    // режим зашифрования данных
        private byte[]          lastBlock;     // последний зашифрованный блок данных

        // конструктор
        public EncryptionCBC(Transform encryption) 
        { 
            // сохранить переданные параметры
            this.encryption = RefObject.addRef(encryption); 
        }
        // освободить выделенные ресурсы
        @Override protected void onClose() throws IOException  
        { 
            // освободить выделенные ресурсы
            RefObject.release(encryption); super.onClose();  
        } 
        // размер блока алгоритма
        @Override public int blockSize() { return encryption.blockSize(); }

        // режим дополнения
        @Override public PaddingMode padding() { return PaddingMode.CTS; }

        // инициализировать алгоритм
        @Override public void init() throws IOException { encryption.init(); lastBlock = null; } 

        @Override public int update(byte[] data, int dataOff, 
            int dataLen, byte[] buf, int bufOff) throws IOException
        {
            // проверить необходимость действий
            int blockSize = blockSize(); if (dataLen == 0) return 0; 

            // проверить корректность данных
            if ((dataLen % blockSize) != 0) throw new IllegalArgumentException(); 

            // определить размер полных блоков кроме последнего
            int cbBlocks = ((dataLen - 1) / blockSize) * blockSize;

            // при наличии последнего блока
            if (lastBlock != null) 
            {
                // скопировать зашифрованный последний блок
                System.arraycopy(lastBlock, 0, buf, bufOff, blockSize); bufOff += blockSize;  

                // зашифровать полные блоки кроме последнего
                encryption.update(data, dataOff, cbBlocks, buf, bufOff);

                // сохранить последний блок
                System.arraycopy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); 

                // зашифровать последний блок
                encryption.update(lastBlock, 0, blockSize, lastBlock, 0); return dataLen; 
            }
            else {
                // зашифровать полные блоки кроме последнего
                encryption.update(data, dataOff, cbBlocks, buf, bufOff);

                // выделить память для последнего блока
                lastBlock = new byte[blockSize]; 

                // сохранить последний блок
                System.arraycopy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); 

                // зашифровать последний блок
                encryption.update(lastBlock, 0, blockSize, lastBlock, 0); return cbBlocks; 
            }
        }
        @Override public int finish(byte[] data, int dataOff, 
            int dataLen, byte[] buf, int bufOff) throws IOException
        {
            // в режиме совместимости
            int blockSize = blockSize(); if (/*legacy &&*/(dataLen % blockSize) == 0)
            {
                // скопировать зашифрованный последний блок
                int cb = 0; if (lastBlock != null) System.arraycopy(lastBlock, 0, buf, bufOff, cb = blockSize);

                // обработать последние данные
                if (dataLen != 0) cb += encryption.finish(data, dataOff, dataLen, buf, bufOff + cb); return cb; 
            }
            else { 
                // при наличии последнего блока
                if (lastBlock != null) 
                {
                    // проверить корректность данных
                    if (dataLen == 0) throw new IllegalArgumentException(); 
                }
                else {
                    // проверить достаточность данных
                    if (dataLen <= blockSize) throw new IllegalArgumentException();
                }
                // определить размер полных блоков кроме последнего
                int cbBlocks = ((dataLen - 1) / blockSize) * blockSize;

                // обработать все блоки, кроме двух последних
                int cb = update(data, dataOff, cbBlocks, buf, bufOff); 

                // перейти на последний блок
                dataOff += cbBlocks; dataLen -= cbBlocks; bufOff += cb; 

                // скопировать часть зашифрованных данных в последний блок
                System.arraycopy(lastBlock, 0, buf, bufOff + blockSize, dataLen);

                // скопировать последний блок для зашифрования
                System.arraycopy(data, dataOff, lastBlock, 0, dataLen); 

                // дополнить последний блок
                for (int i = dataLen; i < blockSize; i++) lastBlock[i] = 0; 

                // зашифровать блок в предпоследний блок
                encryption.update(lastBlock, 0, blockSize, buf, bufOff); 

                // вернуть размер данных
                return cb + blockSize + dataLen; 
            }
        }
    }
    ///////////////////////////////////////////////////////////////////////////////
    // Режим расшифрования CBC с дополнением CTS
    ///////////////////////////////////////////////////////////////////////////////
    public static class DecryptionCBC extends Transform
    {
        private final Transform decryption;	// режим расшифрования данных
        private final byte[]    iv;         // регистр обратной связи
        private byte[]          lastBlock;  // последний блок данных

        // конструктор
        public DecryptionCBC(Transform decryption, byte[] iv) 
        { 
            // сохранить переданные параметры
            this.decryption = RefObject.addRef(decryption); this.iv = iv.clone();
        }
        // освободить выделенные ресурсы
        @Override protected void onClose() throws IOException  
        { 
            // освободить выделенные ресурсы
            RefObject.release(decryption); super.onClose(); 
        } 
        // размер блока алгоритма
        @Override public int blockSize() { return decryption.blockSize(); }

        // режим дополнения
        @Override public PaddingMode padding() { return PaddingMode.CTS; }

        // инициализировать алгоритм
        @Override public void init() throws IOException { decryption.init(); lastBlock = null; } 

        @Override public int update(byte[] data, int dataOff, 
            int dataLen, byte[] buf, int bufOff) throws IOException
        {
            // проверить необходимость действий
            int blockSize = blockSize(); if (dataLen == 0) return 0; 

            // проверить корректность данных
            if ((dataLen % blockSize) != 0) throw new IllegalArgumentException(); 

            // определить размер полных блоков кроме последнего
            int cbBlocks = ((dataLen - 1) / blockSize) * blockSize; if (cbBlocks > 0) 
            {
                // сохранить регистр обратной связи
                System.arraycopy(data, dataOff + cbBlocks - blockSize, iv, 0, blockSize);
            }
            else if (lastBlock != null) 
            { 
                // сохранить регистр обратной связи
                System.arraycopy(lastBlock, 0, iv, 0, blockSize);
            } 
            // при наличии последнего блока
            if (lastBlock != null) 
            { 
                // расшифровать последний блок
                decryption.update(lastBlock, 0, blockSize, lastBlock, 0); 

                // скопировать расшифрованный последний блок
                System.arraycopy(lastBlock, 0, buf, bufOff, blockSize); bufOff += blockSize;  

                // расшифровать полные блоки кроме последнего
                decryption.update(data, dataOff, cbBlocks, buf, bufOff); 

                // сохранить последний блок
                System.arraycopy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); return dataLen; 
            }
            else {
                // расшифровать полные блоки кроме последнего
                decryption.update(data, dataOff, cbBlocks, buf, bufOff); 

                // выделить память для последнего блока
                lastBlock = new byte[blockSize]; 

                // сохранить последний блок
                System.arraycopy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); return cbBlocks; 
            }
        }
        @Override public int finish(byte[] data, int dataOff, 
            int dataLen, byte[] buf, int bufOff) throws IOException
        {
            // в режиме совместимости
            int blockSize = blockSize(); if (/*legacy &&*/(dataLen % blockSize) == 0)
            {
                // обработать сохраненный блок
                int cb = (lastBlock != null) ? decryption.update(lastBlock, 0, blockSize, buf, bufOff) : 0; 

                // обработать последний блок
                if (dataLen != 0) cb += decryption.finish(data, dataOff, dataLen, buf, bufOff + cb); return cb; 
            }
            else { 
                // при наличии последнего блока
                if (lastBlock != null) 
                {
                    // проверить корректность данных
                    if (dataLen == 0) throw new IOException(); 
                }
                // проверить корректность данных
                else if (dataLen <= blockSize) throw new IOException(); 

                // определить размер полных блоков кроме последнего
                int cbBlocks = ((dataLen - 1) / blockSize) * blockSize;

                // обработать все блоки, кроме двух последних
                int cb = update(data, dataOff, cbBlocks, buf, bufOff); 

                // перейти на последний блок
                dataOff += cbBlocks; dataLen -= cbBlocks; bufOff += cb; 

                // расшифровать предпоследний блок
                decryption.update(lastBlock, 0, blockSize, buf, bufOff); 

                // удалить обратную связь режима CBC
                for (int i = 0; i < blockSize; i++) buf[bufOff + i] ^= iv[i];

                // скопировать данные для изменения 
                System.arraycopy(buf, bufOff, buf, bufOff + blockSize, dataLen); 

                // вычислить расшифрованный последний блок
                for (int i = 0; i < dataLen; i++)
                {
                    // применить новую обратную связь режима CBC
                    buf[bufOff + blockSize + i] ^= data[dataOff + i]; 
                }
                // скопировать последний блок для расшифрования
                System.arraycopy(data, dataOff, buf, bufOff, dataLen); 

                // расшифровать предпоследний блок
                decryption.update(buf, bufOff, blockSize, buf, bufOff); 

                // изменить обратную связь режима CBC
                for (int i = 0; i < blockSize; i++) buf[bufOff + i] ^= lastBlock[i] ^ iv[i];

                // вернуть размер данных
                return cb + blockSize + dataLen; 
            }  
        }
    }
}
