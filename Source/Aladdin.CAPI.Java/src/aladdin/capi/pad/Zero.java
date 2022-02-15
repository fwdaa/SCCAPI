package aladdin.capi.pad;
import aladdin.*; 
import aladdin.capi.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Дополнение нулями
///////////////////////////////////////////////////////////////////////////////
public class Zero extends BlockPadding
{ 
    // идентификатор режима
    @Override public PaddingMode mode() { return PaddingMode.ZERO; } 
    
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
        // расшифрование невозможно
        throw new IllegalStateException();
    }
    ///////////////////////////////////////////////////////////////////////////////
    // Режим зашифрования с дополнением нулями
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
        @Override public PaddingMode padding() { return PaddingMode.ZERO; }

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

            // проверить необходимость дополнения
            if (dataLen == 0) return cbBlocks; 

            // скопировать исходные данные
            System.arraycopy(data, dataOff, buf, bufOff, dataLen);

            // дополнить блок
            for (int i = dataLen; i < blockSize; i++) buf[bufOff + i] = 0;

            // зашифровать дополненный блок
            encryption.update(buf, bufOff, blockSize, buf, bufOff); 

            // вернуть размер шифртекста
            return cbBlocks + blockSize; 
        }
    }
}
