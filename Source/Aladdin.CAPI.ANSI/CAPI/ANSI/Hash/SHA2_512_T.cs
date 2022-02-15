using System;
using System.Text;

namespace Aladdin.CAPI.ANSI.Hash
{
    ///////////////////////////////////////////////////////////////////////////////
    // Алгоритм хэширования SHA512/t
    ///////////////////////////////////////////////////////////////////////////////
    public class SHA2_512_T : SHA2_512
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 
    
        // конструктор
        public SHA2_512_T(int bits) { this.bits = bits; } private int bits;  
    
        // размер хэш-значения в байтах
	    public override int HashSize { get { return (bits + 7) / 8; }}
    
	    // инициализировать алгоритм
	    public override void Init()
        {
            switch (bits)
            {
            case 224: 
            {
                // указать начальное заполнение
                ulong H1 = 0x8C3D37C819544DA2L; ulong H2 = 0x73E1996689DCD4D6L; 
                ulong H3 = 0x1DFAB7AE32FF9C82L; ulong H4 = 0x679DD514582F9FCFL; 
                ulong H5 = 0x0F6D2B697BD44DA8L; ulong H6 = 0x77E36F7304C48942L; 
                ulong H7 = 0x3F9D85A86A1D36C8L; ulong H8 = 0x1112E6AD91D692A1L;        
            
                // выполнить инициализацию
                base.Init(H1, H2, H3, H4, H5, H6, H7, H8); break; 
            }
            case 256: 
            {
                // указать начальное заполнение
                ulong H1 = 0x22312194FC2BF72CL; ulong H2 = 0x9F555FA3C84C64C2L; 
                ulong H3 = 0x2393B86B6F53B151L; ulong H4 = 0x963877195940EABDL; 
                ulong H5 = 0x96283EE2A88EFFE3L; ulong H6 = 0xBE5E1E2553863992L; 
                ulong H7 = 0x2B0199FC2C85B8AAL; ulong H8 = 0x0EB72DDC81C52CA2L;        

                // выполнить инициализацию
                base.Init(H1, H2, H3, H4, H5, H6, H7, H8); break;
            }
            default: {
                // выполнить базовую инициализацию
                string text = String.Format("SHA-512/{0}", bits); 

                // закодировать данные
                byte[] data = Encoding.ASCII.GetBytes(text); byte[] hash = new byte[64]; 

                // указать начальное заполнение
                ulong H1 = 0x6a09e667f3bcc908L ^ 0xA5A5A5A5A5A5A5A5L; 
                ulong H2 = 0xbb67ae8584caa73bL ^ 0xA5A5A5A5A5A5A5A5L; 
                ulong H3 = 0x3c6ef372fe94f82bL ^ 0xA5A5A5A5A5A5A5A5L; 
                ulong H4 = 0xa54ff53a5f1d36f1L ^ 0xA5A5A5A5A5A5A5A5L; 
                ulong H5 = 0x510e527fade682d1L ^ 0xA5A5A5A5A5A5A5A5L; 
                ulong H6 = 0x9b05688c2b3e6c1fL ^ 0xA5A5A5A5A5A5A5A5L; 
                ulong H7 = 0x1f83d9abfb41bd6bL ^ 0xA5A5A5A5A5A5A5A5L; 
                ulong H8 = 0x5be0cd19137e2179L ^ 0xA5A5A5A5A5A5A5A5L;        

                // выполнить инициализацию
                base.Init(H1, H2, H3, H4, H5, H6, H7, H8); 

                // вычислить хэш-значение
                Update(data, 0, data.Length); Finish(hash, 0); 

                H1 = Math.Convert.ToUInt64(hash,  0, Endian); 
                H2 = Math.Convert.ToUInt64(hash,  8, Endian); 
                H3 = Math.Convert.ToUInt64(hash, 16, Endian); 
                H4 = Math.Convert.ToUInt64(hash, 24, Endian); 
                H5 = Math.Convert.ToUInt64(hash, 32, Endian); 
                H6 = Math.Convert.ToUInt64(hash, 40, Endian); 
                H7 = Math.Convert.ToUInt64(hash, 48, Endian); 
                H8 = Math.Convert.ToUInt64(hash, 56, Endian); 

                // выполнить инициализацию
                base.Init(H1, H2, H3, H4, H5, H6, H7, H8); break; 
            }}
        }
	    // завершить преобразование
	    public override int Finish(byte[] buf, int bufOff)
	    {
            // завершить преобразование
            byte[] hash = new byte[64]; base.Finish(hash, 0); 
        
            // обнулить неиспользуемое число битов
            if ((bits % 8) != 0) hash[bits / 8] &= (byte)((1 << (bits % 8)) - 1); 
        
            // скопировать хэш-значение
            Array.Copy(hash, 0, buf, bufOff, (bits + 7) / 8); return (bits + 7) / 8; 
	    }
    }
}
