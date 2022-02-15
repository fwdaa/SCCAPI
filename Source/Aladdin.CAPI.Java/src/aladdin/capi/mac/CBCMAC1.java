package aladdin.capi.mac;
import aladdin.*; 
import aladdin.capi.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки CBC-MAC (тип 1)
///////////////////////////////////////////////////////////////////////////////
public class CBCMAC1 extends BlockMac
{
    // блочный алгоритм шифрования и способ дополнения блока
	private final Cipher modeCBC; private final PaddingMode padding;
   
    // преобразование зашифрования, текущее значение и размер имитовставки
    private Transform encryption; private final int macSize; 
    
	// конструктор
	public CBCMAC1(Cipher modeCBC, PaddingMode padding, int macSize) 
    { 
        // проверить корректность параметров
        if (macSize > modeCBC.blockSize()) throw new IllegalArgumentException();

        // сохранить переданные параметры
        this.modeCBC = RefObject.addRef(modeCBC); 
        
        // сохранить переданные параметры
        this.padding = padding; this.macSize = macSize;
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException
    { 
        // освободить выделенные ресурсы
        RefObject.release(modeCBC); 
            
        // освободить выделенные ресурсы
        RefObject.release(encryption); super.onClose();
    } 
	// размер хэш-значения в байтах
	@Override public final int macSize() { return macSize; }  
	
    // тип ключа
	@Override public SecretKeyFactory keyFactory() { return modeCBC.keyFactory(); }
	// размеры ключей в байтах
	@Override public final int[] keySizes() { return modeCBC.keySizes(); } 

	// размер блока в байтах
	@Override public final int blockSize() { return modeCBC.blockSize(); } 

	// инициализировать алгоритм
	@Override public void init(ISecretKey key) throws IOException, InvalidKeyException
    {
        // создать преобразование зашифрования
        super.init(key); encryption = modeCBC.createEncryption(key, PaddingMode.NONE); encryption.init();
    }
	// обработать блок данных
	@Override protected void update(byte[] data, int dataOff) throws IOException
    {
        // выделить блок для преобразования
        byte[] mac = new byte[modeCBC.blockSize()]; 
        
        // выполнить преобразование
        encryption.update(data, dataOff, blockSize(), mac, 0); 
    }
	// завершить преобразование
	@Override protected void finish(byte[] data, 
        int dataOff, int dataLen, byte[] buf, int bufOff) throws IOException
    {
        // выделить блок для преобразования
        byte[] mac = new byte[modeCBC.blockSize()]; 
        
        // при отсутствии дополнения
        if (padding == PaddingMode.NONE)
        { 
            // выполнить преобразование
            encryption.finish(data, dataOff, dataLen, mac, 0);
        }
        else { 
            // создать дополнительный блок
            byte[] block = new byte[mac.length]; 
                
            // при кратном числе блоков                
            if ((dataLen % block.length) == 0) { block[0] = (byte)0x80; 
                
                // выполнить преобразование
                if (dataLen > 0) encryption.update(data, dataOff, dataLen, mac, 0);
            }
            else { block[dataLen] = (byte)0x80; 

                // скопировать неполный блок
                System.arraycopy(data, dataOff, block, 0, dataLen); 
            }
            // выполнить преобразование
            encryption.finish(block, 0, block.length, mac, 0);
        }
        // скопировать вычисленную имитовставку
        System.arraycopy(mac, 0, buf, bufOff, macSize);
        
		// освободить выделенные ресурсы
		RefObject.release(encryption); encryption = null; 
    }
}
