package aladdin.capi.pad;
import aladdin.*; 
import aladdin.capi.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Дополнение ISO 9797-1.2
///////////////////////////////////////////////////////////////////////////////
public class ISO9797 extends BlockPadding
{ 
    // идентификатор режима
    @Override public PaddingMode mode() { return PaddingMode.ISO9797; } 
    
    // алгоритм зашифрования данных
    @Override public Transform createEncryption(Transform encryption, CipherMode mode)
    {
        // вызвать базовую функцию
        Transform transform = super.createEncryption(encryption, mode); 

        // алгоритм зашифрования данных
        return (transform == null) ? new Encryption(encryption) : transform; 
    }
    // алгоритм расшифрования данных
    @Override public Transform createDecryption(Transform decryption, CipherMode mode)
    {
        // вызвать базовую функцию
        Transform transform = super.createDecryption(decryption, mode); 

        // алгоритм расшифрования данных
        return (transform == null) ? new Decryption(decryption) : transform; 
    }
    ///////////////////////////////////////////////////////////////////////////////
    // Режим зашифрования с дополнением ISO 9797-1.2
    ///////////////////////////////////////////////////////////////////////////////
    public static class Encryption extends Transform
    {
        // режим зашифрования данных
        private final Transform encryption; 

        // конструктор
        public Encryption(Transform encryption) 
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
        @Override public PaddingMode padding() { return PaddingMode.ISO9797; }

        // инициализировать алгоритм
        @Override public void init() throws IOException { encryption.init(); } 

        @Override public int update(byte[] data, int dataOff, 
            int dataLen, byte[] buf, int bufOff) throws IOException
        {
            // зашифровать полные блоки
            encryption.update(data, dataOff, dataLen, buf, bufOff); return dataLen; 
        }
        @Override public int finish(byte[] data, int dataOff, 
            int dataLen, byte[] buf, int bufOff) throws IOException
        {
            // определить размер полных блоков
            int blockSize = blockSize(); int cbBlocks = (dataLen / blockSize) * blockSize; 

            // преобразовать полные блоки
            encryption.update(data, dataOff, cbBlocks, buf, bufOff); 

            // перейти на неполный блок
            dataOff += cbBlocks; dataLen -= cbBlocks; bufOff += cbBlocks;

            // скопировать исходные данные
            System.arraycopy(data, dataOff, buf, bufOff, dataLen);

            // указать граничное значение
            buf[bufOff + dataLen] = (byte)0x80; 

            // дополнить блок
            for (int i = dataLen + 1; i < blockSize; i++) buf[bufOff + i] = 0;

            // зашифровать дополненный блок
            encryption.update(buf, bufOff, blockSize, buf, bufOff); 

            // вернуть размер шифртекста
            return cbBlocks + blockSize; 
        }
    }
    ///////////////////////////////////////////////////////////////////////////////
    // Режим расшифрования с дополнением ISO 9797-1.2
    ///////////////////////////////////////////////////////////////////////////////
    public static class Decryption extends Transform
    {
        // режим расшифрования данных и последний блок данных
        private final Transform decryption; private byte[] lastBlock;    

        // конструктор
        public Decryption(Transform decryption) 
        { 
            // сохранить переданные параметры
            this.decryption = RefObject.addRef(decryption); lastBlock = null; 
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
        @Override public PaddingMode padding() { return PaddingMode.ISO9797; }

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
            // проверить корректность данных
            if (dataLen == 0 && lastBlock == null) throw new IOException(); 

            // проверить корректность данных
            int blockSize = blockSize(); if ((dataLen % blockSize) != 0) 
            {
                // при ошибке выбросить исключение
                throw new IOException();
            }
            // расшифровать данные
            int total = update(data, dataOff, dataLen, buf, bufOff); 

            // пропустить завершающие заполнители
            int cb = blockSize - 1; while (cb >= 0 && lastBlock[cb] == 0) cb--; 

            // проверить корректность данных
            if (cb < 0 || lastBlock[cb] == (byte)0x80) throw new IOException();

            // скопировать неполный блок
            System.arraycopy(lastBlock, 0, buf, bufOff + total, cb); return total + cb;
        }
    }
}