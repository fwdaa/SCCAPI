package aladdin.capi.ansi.hash;
import aladdin.math.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования SHA512/t
///////////////////////////////////////////////////////////////////////////////
public class SHA2_512_T extends SHA2_512
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
    // конструктор
    public SHA2_512_T(int bits) { this.bits = bits; } private final int bits;  
    
    // размер хэш-значения в байтах
	@Override public int hashSize() { return (bits + 7) / 8; }  
    
	// инициализировать алгоритм
	@Override public void init() throws IOException
    {
        switch (bits)
        {
        case 224: 
        {
            // указать начальное заполнение
            long H1 = 0x8C3D37C819544DA2L; long H2 = 0x73E1996689DCD4D6L; 
            long H3 = 0x1DFAB7AE32FF9C82L; long H4 = 0x679DD514582F9FCFL; 
            long H5 = 0x0F6D2B697BD44DA8L; long H6 = 0x77E36F7304C48942L; 
            long H7 = 0x3F9D85A86A1D36C8L; long H8 = 0x1112E6AD91D692A1L;        
            
            // выполнить инициализацию
            super.init(H1, H2, H3, H4, H5, H6, H7, H8); break; 
        }
        case 256: 
        {
            // указать начальное заполнение
            long H1 = 0x22312194FC2BF72CL; long H2 = 0x9F555FA3C84C64C2L; 
            long H3 = 0x2393B86B6F53B151L; long H4 = 0x963877195940EABDL; 
            long H5 = 0x96283EE2A88EFFE3L; long H6 = 0xBE5E1E2553863992L; 
            long H7 = 0x2B0199FC2C85B8AAL; long H8 = 0x0EB72DDC81C52CA2L;        

            // выполнить инициализацию
            super.init(H1, H2, H3, H4, H5, H6, H7, H8); break; 
        }
        default: {
            // выполнить базовую инициализацию
            String text = String.format("SHA-512/%1$d", bits); 

            // закодировать данные
            byte[] data = text.getBytes("ASCII"); byte[] hash = new byte[64]; 

            // указать начальное заполнение
            long H1 = 0x6a09e667f3bcc908L ^ 0xA5A5A5A5A5A5A5A5L; 
            long H2 = 0xbb67ae8584caa73bL ^ 0xA5A5A5A5A5A5A5A5L; 
            long H3 = 0x3c6ef372fe94f82bL ^ 0xA5A5A5A5A5A5A5A5L; 
            long H4 = 0xa54ff53a5f1d36f1L ^ 0xA5A5A5A5A5A5A5A5L; 
            long H5 = 0x510e527fade682d1L ^ 0xA5A5A5A5A5A5A5A5L; 
            long H6 = 0x9b05688c2b3e6c1fL ^ 0xA5A5A5A5A5A5A5A5L; 
            long H7 = 0x1f83d9abfb41bd6bL ^ 0xA5A5A5A5A5A5A5A5L; 
            long H8 = 0x5be0cd19137e2179L ^ 0xA5A5A5A5A5A5A5A5L;        

            // выполнить инициализацию
            super.init(H1, H2, H3, H4, H5, H6, H7, H8); 

            // вычислить хэш-значение
            update(data, 0, data.length); finish(hash, 0); 

            H1 = Convert.toInt64(hash,  0, ENDIAN); 
            H2 = Convert.toInt64(hash,  8, ENDIAN); 
            H3 = Convert.toInt64(hash, 16, ENDIAN); 
            H4 = Convert.toInt64(hash, 24, ENDIAN); 
            H5 = Convert.toInt64(hash, 32, ENDIAN); 
            H6 = Convert.toInt64(hash, 40, ENDIAN); 
            H7 = Convert.toInt64(hash, 48, ENDIAN); 
            H8 = Convert.toInt64(hash, 56, ENDIAN); 

            // выполнить инициализацию
            super.init(H1, H2, H3, H4, H5, H6, H7, H8); break;
        }}
    }
	// завершить преобразование
	@Override public int finish(byte[] buf, int bufOff) throws IOException
	{
        // завершить преобразование
        byte[] hash = new byte[64]; super.finish(hash, 0); 
        
        // обнулить неиспользуемое число битов
        if ((bits % 8) != 0) hash[bits / 8] &= (1 << (bits % 8)) - 1; 
        
        // скопировать хэш-значение
        System.arraycopy(hash, 0, buf, bufOff, (bits + 7) / 8); return (bits + 7) / 8; 
	}
}
