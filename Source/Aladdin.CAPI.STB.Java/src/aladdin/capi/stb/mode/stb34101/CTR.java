package aladdin.capi.stb.mode.stb34101;
import aladdin.capi.*;
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Режим CTR
//////////////////////////////////////////////////////////////////////////////
public class CTR extends aladdin.capi.mode.CTR
{
    // конструктор
	public CTR(Cipher engine, CipherMode.CTR mode)
	{ 
        // сохранить переданные параметры
        super(engine, mode); 
	}
    // преобразование зашифрования
    @Override protected aladdin.capi.Transform createEncryption(ISecretKey key) 
        throws IOException, InvalidKeyException 
    { 
        // преобразование зашифрования
        return new Transform(engine(), key, mode()); 
    }
    // преобразование расшифрования
    @Override protected aladdin.capi.Transform createDecryption(ISecretKey key) 
        throws IOException, InvalidKeyException 
    { 
        // преобразование расшифрования
        return new Transform(engine(), key, mode()); 
    }
    ///////////////////////////////////////////////////////////////////////////////
    // Режим преобразования CTR
    ///////////////////////////////////////////////////////////////////////////////
    public static class Transform extends aladdin.capi.mode.CTR.Transform
    {
        // конструктор
        public Transform(Cipher engine, ISecretKey key, CipherMode.CTR parameters) 
            throws IOException, InvalidKeyException
        { 
            // сохранить переданные параметры
            super(engine, key, parameters); 
        } 
        @Override public void init() throws IOException
        {  
            // зашифровать синхропосылку
            super.init(); encryption.update(iv(), 0, iv().length, iv(), 0);
        }
        @Override protected void update(
            byte[] data, int dataOff, byte[] buf, int bufOff) throws IOException 
        {
            // выделить вспомогательный буфер
            byte[] copy = new byte[blockSize()]; increment(iv());

            // зашифровать регистр, увеличить регистр 
            encryption.update(iv(), 0, copy.length, copy, 0); 

            // для всех байтов
            for (int j = 0; j < blockSize(); j++) 
            {
                // выполнить поразрядное сложение
                buf[bufOff + j] = (byte)(data[dataOff + j] ^ copy[j]); 
            }
        }
        // увеличить значение регистра
        @Override protected void increment(byte[] iv)
        {
            // для всех разрядов регистра
            for (int i = 0; i < iv.length; i++)
            {
                // увеличить разряд регистра
                iv[i] = (byte)(iv[i] + 1); if (iv[i] != 0) break; 
            }
        }
    }
}
