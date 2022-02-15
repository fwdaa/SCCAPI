package aladdin.capi.ansi.hash;
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования MD2
///////////////////////////////////////////////////////////////////////////////
public class MD2 extends BlockHash
{
     // 256-byte random permutation constructed from the digits of PI
    private static final byte[] S = {
      (byte) 41,(byte) 46,(byte) 67,(byte)201,(byte)162,(byte)216,(byte)124,(byte)  1,
      (byte) 61,(byte) 54,(byte) 84,(byte)161,(byte)236,(byte)240,(byte)  6,(byte) 19,
      (byte) 98,(byte)167,(byte)  5,(byte)243,(byte)192,(byte)199,(byte)115,(byte)140,
      (byte)152,(byte)147,(byte) 43,(byte)217,(byte)188,(byte) 76,(byte)130,(byte)202,
      (byte) 30,(byte)155,(byte) 87,(byte) 60,(byte)253,(byte)212,(byte)224,(byte) 22,
      (byte)103,(byte) 66,(byte)111,(byte) 24,(byte)138,(byte) 23,(byte)229,(byte) 18,
      (byte)190,(byte) 78,(byte)196,(byte)214,(byte)218,(byte)158,(byte)222,(byte) 73,
      (byte)160,(byte)251,(byte)245,(byte)142,(byte)187,(byte) 47,(byte)238,(byte)122,
      (byte)169,(byte)104,(byte)121,(byte)145,(byte) 21,(byte)178,(byte)  7,(byte) 63,
      (byte)148,(byte)194,(byte) 16,(byte)137,(byte) 11,(byte) 34,(byte) 95,(byte) 33,
      (byte)128,(byte)127,(byte) 93,(byte)154,(byte) 90,(byte)144,(byte) 50,(byte) 39,
      (byte) 53,(byte) 62,(byte)204,(byte)231,(byte)191,(byte)247,(byte)151,(byte)  3,
      (byte)255,(byte) 25,(byte) 48,(byte)179,(byte) 72,(byte)165,(byte)181,(byte)209,
      (byte)215,(byte) 94,(byte)146,(byte) 42,(byte)172,(byte) 86,(byte)170,(byte)198,
      (byte) 79,(byte)184,(byte) 56,(byte)210,(byte)150,(byte)164,(byte)125,(byte)182,
      (byte)118,(byte)252,(byte)107,(byte)226,(byte)156,(byte)116,(byte)  4,(byte)241,
      (byte) 69,(byte)157,(byte)112,(byte) 89,(byte)100,(byte)113,(byte)135,(byte) 32,
      (byte)134,(byte) 91,(byte)207,(byte)101,(byte)230,(byte) 45,(byte)168,(byte)  2,
      (byte) 27,(byte) 96,(byte) 37,(byte)173,(byte)174,(byte)176,(byte)185,(byte)246,
      (byte) 28,(byte) 70,(byte) 97,(byte)105,(byte) 52,(byte) 64,(byte)126,(byte) 15,
      (byte) 85,(byte) 71,(byte)163,(byte) 35,(byte)221,(byte) 81,(byte)175,(byte) 58,
      (byte)195,(byte) 92,(byte)249,(byte)206,(byte)186,(byte)197,(byte)234,(byte) 38,
      (byte) 44,(byte) 83,(byte) 13,(byte)110,(byte)133,(byte) 40,(byte)132,(byte)  9,
      (byte)211,(byte)223,(byte)205,(byte)244,(byte) 65,(byte)129,(byte) 77,(byte) 82,
      (byte)106,(byte)220,(byte) 55,(byte)200,(byte)108,(byte)193,(byte)171,(byte)250,
      (byte) 36,(byte)225,(byte)123,(byte)  8,(byte) 12,(byte)189,(byte)177,(byte) 74,
      (byte)120,(byte)136,(byte)149,(byte)139,(byte)227,(byte) 99,(byte)232,(byte)109,
      (byte)233,(byte)203,(byte)213,(byte)254,(byte) 59,(byte)  0,(byte) 29,(byte) 57,
      (byte)242,(byte)239,(byte)183,(byte) 14,(byte)102,(byte) 88,(byte)208,(byte)228,
      (byte)166,(byte)119,(byte)114,(byte)248,(byte)235,(byte)117,(byte) 75,(byte) 10,
      (byte) 49,(byte) 68,(byte) 80,(byte)180,(byte)143,(byte)237,(byte) 31,(byte) 26,
      (byte)219,(byte)153,(byte)141,(byte) 51,(byte)159,(byte) 17,(byte)131,(byte) 20
    };
    private final byte[] X = new byte[48]; // X buffer
    private final byte[] C = new byte[16]; // check sum
    
    // размер хэш-значения в байтах
	@Override public int hashSize() { return 16; }  
	
	// размер блока в байтах
	@Override public int blockSize() { return 16; } 

	// инициализировать алгоритм
	@Override public void init() throws IOException { super.init(); 

        for (int i = 0; i != X.length; i++) X[i] = 0;
        for (int i = 0; i != C.length; i++) C[i] = 0;
    }
	// обработать блок данных
	@Override protected void update(byte[] data, int dataOff)  
    {
        // обработать контрольную сумму
        for (int i = 0, L = C[15]; i < 16; i++)
        {
            C[i] ^= S[(data[dataOff + i] ^ L) & 0xff]; L = C[i];
        }        
        // обработать блок данных
        processBlock(data, dataOff);
    }
	// завершить преобразование
	@Override protected void finish(
        byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
    {
        // для последнего полного блока 
        int blockSize = blockSize(); if (dataLen == blockSize) 
        {
            // обработать последний полный блок
            update(data, dataOff); dataOff += blockSize; dataLen -= blockSize;
        }
        // определить число недостающих байтов
        byte paddingByte = (byte)(blockSize - dataLen);
        
        // выделить буфер для дополнения
        byte[] buffer = new byte[blockSize]; 

        // скопировать данные
        System.arraycopy(data, dataOff, buffer, 0, dataLen);

        // выполнить дополнение
        for (int i = dataLen; i < blockSize; i++) buffer[i] = paddingByte; 
        
        // обработать блок
        update(buffer, 0); processBlock(C, 0); 

        // скопировать хэш-значение
        System.arraycopy(X, 0, buf, bufOff, 16);
    }
    private void processBlock(byte[] data, int dataOff)
    {
        for (int i = 0; i < 16; i++)
        {
            X[i + 16] = (byte)(data[dataOff + i] ^ 0x00); 
            X[i + 32] = (byte)(data[dataOff + i] ^ X[i]);
        }
        for (int j = 0, t = 0; j < 18; j++)
        {
            for (int k = 0; k < 48; k++)
            {
                t = X[k] ^= S[t]; t = t & 0xff;
            }
            t = (t + j) % 256;
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тесты известного ответа
    ////////////////////////////////////////////////////////////////////////////
    public static void test(Hash hashAlgorithm) throws Exception
    {
        knownTest(hashAlgorithm, 1, 
            "", new byte[] { 
            (byte)0x83, (byte)0x50, (byte)0xe5, (byte)0xa3, 
            (byte)0xe2, (byte)0x4c, (byte)0x15, (byte)0x3d, 
            (byte)0xf2, (byte)0x27, (byte)0x5c, (byte)0x9f, 
            (byte)0x80, (byte)0x69, (byte)0x27, (byte)0x73
        }); 
        knownTest(hashAlgorithm, 1, 
            "a", new byte[] { 
            (byte)0x32, (byte)0xec, (byte)0x01, (byte)0xec, 
            (byte)0x4a, (byte)0x6d, (byte)0xac, (byte)0x72, 
            (byte)0xc0, (byte)0xab, (byte)0x96, (byte)0xfb, 
            (byte)0x34, (byte)0xc0, (byte)0xb5, (byte)0xd1
        }); 
        knownTest(hashAlgorithm, 1, 
            "abc", new byte[] { 
            (byte)0xda, (byte)0x85, (byte)0x3b, (byte)0x0d, 
            (byte)0x3f, (byte)0x88, (byte)0xd9, (byte)0x9b, 
            (byte)0x30, (byte)0x28, (byte)0x3a, (byte)0x69, 
            (byte)0xe6, (byte)0xde, (byte)0xd6, (byte)0xbb 
        }); 
        knownTest(hashAlgorithm, 1, 
            "message digest", new byte[] { 
            (byte)0xab, (byte)0x4f, (byte)0x49, (byte)0x6b, 
            (byte)0xfb, (byte)0x2a, (byte)0x53, (byte)0x0b, 
            (byte)0x21, (byte)0x9f, (byte)0xf3, (byte)0x30, 
            (byte)0x31, (byte)0xfe, (byte)0x06, (byte)0xb0 
        }); 
        knownTest(hashAlgorithm, 1, 
            "abcdefghijklmnopqrstuvwxyz", new byte[] { 
            (byte)0x4e, (byte)0x8d, (byte)0xdf, (byte)0xf3, 
            (byte)0x65, (byte)0x02, (byte)0x92, (byte)0xab, 
            (byte)0x5a, (byte)0x41, (byte)0x08, (byte)0xc3, 
            (byte)0xaa, (byte)0x47, (byte)0x94, (byte)0x0b
        }); 
        knownTest(hashAlgorithm, 1, 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + 
            "abcdefghijklmnopqrstuvwxyz0123456789", new byte[] { 
            (byte)0xda, (byte)0x33, (byte)0xde, (byte)0xf2, 
            (byte)0xa4, (byte)0x2d, (byte)0xf1, (byte)0x39, 
            (byte)0x75, (byte)0x35, (byte)0x28, (byte)0x46, 
            (byte)0xc3, (byte)0x03, (byte)0x38, (byte)0xcd
        }); 
        knownTest(hashAlgorithm, 1, 
            "1234567890123456789012345678901234567890" + 
            "1234567890123456789012345678901234567890", new byte[] { 
            (byte)0xd5, (byte)0x97, (byte)0x6f, (byte)0x79, 
            (byte)0xd8, (byte)0x3d, (byte)0x3a, (byte)0x0d, 
            (byte)0xc9, (byte)0x80, (byte)0x6c, (byte)0x3c, 
            (byte)0x66, (byte)0xf3, (byte)0xef, (byte)0xd8
        }); 
    }
}

