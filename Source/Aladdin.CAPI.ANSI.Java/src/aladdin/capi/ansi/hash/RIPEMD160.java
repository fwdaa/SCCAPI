package aladdin.capi.ansi.hash;
import aladdin.math.*;
import aladdin.capi.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования RIPEMD160
///////////////////////////////////////////////////////////////////////////////
public class RIPEMD160 extends BlockHash
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 

    // rotate int x left n bits.
    private static int RL(int x, int n)
    {
        return (x << n) | (x >>> (32 - n));
    }
    // f1,f2,f3,f4,f5 are the basic RIPEMD160 functions.
    // rounds 0-15
    private static int f1(int x, int y, int z)
    {
        return x ^ y ^ z;
    }
    // rounds 16-31
    private static int f2(int x, int y, int z)
    {
        return (x & y) | (~x & z);
    }
    // rounds 32-47
    private static int f3(int x, int y, int z)
    {
        return (x | ~y) ^ z;
    }
    // rounds 48-63
    private static int f4(int x, int y, int z)
    {
        return (x & z) | (y & ~z);
    }
    // rounds 64-79
    private static int f5(int x, int y, int z)
    {
        return x ^ (y | ~z);
    }
    private long byteCount; private int H0, H1, H2, H3, H4;

    // размер хэш-значения в байтах
	@Override public int hashSize() { return 20; }  
	
	// размер блока в байтах
	@Override public int blockSize() { return 64; } 

	// инициализировать алгоритм
	@Override public void init() throws IOException
    { 
        super.init(); byteCount = 0;  

        H0 = 0x67452301; H1 = 0xefcdab89;
        H2 = 0x98badcfe; H3 = 0x10325476;
        H4 = 0xc3d2e1f0;
    }
	// обработать блок данных
	@Override protected void update(byte[] data, int dataOff)  
    {
        // выделить буфер требуемого размера
        int[] X = new int[16]; byteCount += blockSize();
        
        // скопировать данные в буфер
        for (int i = 0; i < X.length; i++)
        {
            // скопировать данные в буфер
            X[i] = Convert.toInt32(data, dataOff + 4 * i, ENDIAN); 
        }
        int a = H0; int aa = H0;
        int b = H1; int bb = H1;
        int c = H2; int cc = H2;
        int d = H3; int dd = H3;
        int e = H4; int ee = H4;
        //
        // Rounds 1 - 16
        //
        // left
        a = RL(a + f1(b,c,d) + X[ 0], 11) + e; c = RL(c, 10);
        e = RL(e + f1(a,b,c) + X[ 1], 14) + d; b = RL(b, 10);
        d = RL(d + f1(e,a,b) + X[ 2], 15) + c; a = RL(a, 10);
        c = RL(c + f1(d,e,a) + X[ 3], 12) + b; e = RL(e, 10);
        b = RL(b + f1(c,d,e) + X[ 4],  5) + a; d = RL(d, 10);
        a = RL(a + f1(b,c,d) + X[ 5],  8) + e; c = RL(c, 10);
        e = RL(e + f1(a,b,c) + X[ 6],  7) + d; b = RL(b, 10);
        d = RL(d + f1(e,a,b) + X[ 7],  9) + c; a = RL(a, 10);
        c = RL(c + f1(d,e,a) + X[ 8], 11) + b; e = RL(e, 10);
        b = RL(b + f1(c,d,e) + X[ 9], 13) + a; d = RL(d, 10);
        a = RL(a + f1(b,c,d) + X[10], 14) + e; c = RL(c, 10);
        e = RL(e + f1(a,b,c) + X[11], 15) + d; b = RL(b, 10);
        d = RL(d + f1(e,a,b) + X[12],  6) + c; a = RL(a, 10);
        c = RL(c + f1(d,e,a) + X[13],  7) + b; e = RL(e, 10);
        b = RL(b + f1(c,d,e) + X[14],  9) + a; d = RL(d, 10);
        a = RL(a + f1(b,c,d) + X[15],  8) + e; c = RL(c, 10);

        // right
        aa = RL(aa + f5(bb,cc,dd) + X[ 5] + 0x50a28be6,  8) + ee; cc = RL(cc, 10);
        ee = RL(ee + f5(aa,bb,cc) + X[14] + 0x50a28be6,  9) + dd; bb = RL(bb, 10);
        dd = RL(dd + f5(ee,aa,bb) + X[ 7] + 0x50a28be6,  9) + cc; aa = RL(aa, 10);
        cc = RL(cc + f5(dd,ee,aa) + X[ 0] + 0x50a28be6, 11) + bb; ee = RL(ee, 10);
        bb = RL(bb + f5(cc,dd,ee) + X[ 9] + 0x50a28be6, 13) + aa; dd = RL(dd, 10);
        aa = RL(aa + f5(bb,cc,dd) + X[ 2] + 0x50a28be6, 15) + ee; cc = RL(cc, 10);
        ee = RL(ee + f5(aa,bb,cc) + X[11] + 0x50a28be6, 15) + dd; bb = RL(bb, 10);
        dd = RL(dd + f5(ee,aa,bb) + X[ 4] + 0x50a28be6,  5) + cc; aa = RL(aa, 10);
        cc = RL(cc + f5(dd,ee,aa) + X[13] + 0x50a28be6,  7) + bb; ee = RL(ee, 10);
        bb = RL(bb + f5(cc,dd,ee) + X[ 6] + 0x50a28be6,  7) + aa; dd = RL(dd, 10);
        aa = RL(aa + f5(bb,cc,dd) + X[15] + 0x50a28be6,  8) + ee; cc = RL(cc, 10);
        ee = RL(ee + f5(aa,bb,cc) + X[ 8] + 0x50a28be6, 11) + dd; bb = RL(bb, 10);
        dd = RL(dd + f5(ee,aa,bb) + X[ 1] + 0x50a28be6, 14) + cc; aa = RL(aa, 10);
        cc = RL(cc + f5(dd,ee,aa) + X[10] + 0x50a28be6, 14) + bb; ee = RL(ee, 10);
        bb = RL(bb + f5(cc,dd,ee) + X[ 3] + 0x50a28be6, 12) + aa; dd = RL(dd, 10);
        aa = RL(aa + f5(bb,cc,dd) + X[12] + 0x50a28be6,  6) + ee; cc = RL(cc, 10);
        //
        // Rounds 16-31
        //
        // left
        e = RL(e + f2(a,b,c) + X[ 7] + 0x5a827999,  7) + d; b = RL(b, 10);
        d = RL(d + f2(e,a,b) + X[ 4] + 0x5a827999,  6) + c; a = RL(a, 10);
        c = RL(c + f2(d,e,a) + X[13] + 0x5a827999,  8) + b; e = RL(e, 10);
        b = RL(b + f2(c,d,e) + X[ 1] + 0x5a827999, 13) + a; d = RL(d, 10);
        a = RL(a + f2(b,c,d) + X[10] + 0x5a827999, 11) + e; c = RL(c, 10);
        e = RL(e + f2(a,b,c) + X[ 6] + 0x5a827999,  9) + d; b = RL(b, 10);
        d = RL(d + f2(e,a,b) + X[15] + 0x5a827999,  7) + c; a = RL(a, 10);
        c = RL(c + f2(d,e,a) + X[ 3] + 0x5a827999, 15) + b; e = RL(e, 10);
        b = RL(b + f2(c,d,e) + X[12] + 0x5a827999,  7) + a; d = RL(d, 10);
        a = RL(a + f2(b,c,d) + X[ 0] + 0x5a827999, 12) + e; c = RL(c, 10);
        e = RL(e + f2(a,b,c) + X[ 9] + 0x5a827999, 15) + d; b = RL(b, 10);
        d = RL(d + f2(e,a,b) + X[ 5] + 0x5a827999,  9) + c; a = RL(a, 10);
        c = RL(c + f2(d,e,a) + X[ 2] + 0x5a827999, 11) + b; e = RL(e, 10);
        b = RL(b + f2(c,d,e) + X[14] + 0x5a827999,  7) + a; d = RL(d, 10);
        a = RL(a + f2(b,c,d) + X[11] + 0x5a827999, 13) + e; c = RL(c, 10);
        e = RL(e + f2(a,b,c) + X[ 8] + 0x5a827999, 12) + d; b = RL(b, 10);

        // right
        ee = RL(ee + f4(aa,bb,cc) + X[ 6] + 0x5c4dd124,  9) + dd; bb = RL(bb, 10);
        dd = RL(dd + f4(ee,aa,bb) + X[11] + 0x5c4dd124, 13) + cc; aa = RL(aa, 10);
        cc = RL(cc + f4(dd,ee,aa) + X[ 3] + 0x5c4dd124, 15) + bb; ee = RL(ee, 10);
        bb = RL(bb + f4(cc,dd,ee) + X[ 7] + 0x5c4dd124,  7) + aa; dd = RL(dd, 10);
        aa = RL(aa + f4(bb,cc,dd) + X[ 0] + 0x5c4dd124, 12) + ee; cc = RL(cc, 10);
        ee = RL(ee + f4(aa,bb,cc) + X[13] + 0x5c4dd124,  8) + dd; bb = RL(bb, 10);
        dd = RL(dd + f4(ee,aa,bb) + X[ 5] + 0x5c4dd124,  9) + cc; aa = RL(aa, 10);
        cc = RL(cc + f4(dd,ee,aa) + X[10] + 0x5c4dd124, 11) + bb; ee = RL(ee, 10);
        bb = RL(bb + f4(cc,dd,ee) + X[14] + 0x5c4dd124,  7) + aa; dd = RL(dd, 10);
        aa = RL(aa + f4(bb,cc,dd) + X[15] + 0x5c4dd124,  7) + ee; cc = RL(cc, 10);
        ee = RL(ee + f4(aa,bb,cc) + X[ 8] + 0x5c4dd124, 12) + dd; bb = RL(bb, 10);
        dd = RL(dd + f4(ee,aa,bb) + X[12] + 0x5c4dd124,  7) + cc; aa = RL(aa, 10);
        cc = RL(cc + f4(dd,ee,aa) + X[ 4] + 0x5c4dd124,  6) + bb; ee = RL(ee, 10);
        bb = RL(bb + f4(cc,dd,ee) + X[ 9] + 0x5c4dd124, 15) + aa; dd = RL(dd, 10);
        aa = RL(aa + f4(bb,cc,dd) + X[ 1] + 0x5c4dd124, 13) + ee; cc = RL(cc, 10);
        ee = RL(ee + f4(aa,bb,cc) + X[ 2] + 0x5c4dd124, 11) + dd; bb = RL(bb, 10);
        //
        // Rounds 32-47
        //
        // left
        d = RL(d + f3(e,a,b) + X[ 3] + 0x6ed9eba1, 11) + c; a = RL(a, 10);
        c = RL(c + f3(d,e,a) + X[10] + 0x6ed9eba1, 13) + b; e = RL(e, 10);
        b = RL(b + f3(c,d,e) + X[14] + 0x6ed9eba1,  6) + a; d = RL(d, 10);
        a = RL(a + f3(b,c,d) + X[ 4] + 0x6ed9eba1,  7) + e; c = RL(c, 10);
        e = RL(e + f3(a,b,c) + X[ 9] + 0x6ed9eba1, 14) + d; b = RL(b, 10);
        d = RL(d + f3(e,a,b) + X[15] + 0x6ed9eba1,  9) + c; a = RL(a, 10);
        c = RL(c + f3(d,e,a) + X[ 8] + 0x6ed9eba1, 13) + b; e = RL(e, 10);
        b = RL(b + f3(c,d,e) + X[ 1] + 0x6ed9eba1, 15) + a; d = RL(d, 10);
        a = RL(a + f3(b,c,d) + X[ 2] + 0x6ed9eba1, 14) + e; c = RL(c, 10);
        e = RL(e + f3(a,b,c) + X[ 7] + 0x6ed9eba1,  8) + d; b = RL(b, 10);
        d = RL(d + f3(e,a,b) + X[ 0] + 0x6ed9eba1, 13) + c; a = RL(a, 10);
        c = RL(c + f3(d,e,a) + X[ 6] + 0x6ed9eba1,  6) + b; e = RL(e, 10);
        b = RL(b + f3(c,d,e) + X[13] + 0x6ed9eba1,  5) + a; d = RL(d, 10);
        a = RL(a + f3(b,c,d) + X[11] + 0x6ed9eba1, 12) + e; c = RL(c, 10);
        e = RL(e + f3(a,b,c) + X[ 5] + 0x6ed9eba1,  7) + d; b = RL(b, 10);
        d = RL(d + f3(e,a,b) + X[12] + 0x6ed9eba1,  5) + c; a = RL(a, 10);

        // right
        dd = RL(dd + f3(ee,aa,bb) + X[15] + 0x6d703ef3,  9) + cc; aa = RL(aa, 10);
        cc = RL(cc + f3(dd,ee,aa) + X[ 5] + 0x6d703ef3,  7) + bb; ee = RL(ee, 10);
        bb = RL(bb + f3(cc,dd,ee) + X[ 1] + 0x6d703ef3, 15) + aa; dd = RL(dd, 10);
        aa = RL(aa + f3(bb,cc,dd) + X[ 3] + 0x6d703ef3, 11) + ee; cc = RL(cc, 10);
        ee = RL(ee + f3(aa,bb,cc) + X[ 7] + 0x6d703ef3,  8) + dd; bb = RL(bb, 10);
        dd = RL(dd + f3(ee,aa,bb) + X[14] + 0x6d703ef3,  6) + cc; aa = RL(aa, 10);
        cc = RL(cc + f3(dd,ee,aa) + X[ 6] + 0x6d703ef3,  6) + bb; ee = RL(ee, 10);
        bb = RL(bb + f3(cc,dd,ee) + X[ 9] + 0x6d703ef3, 14) + aa; dd = RL(dd, 10);
        aa = RL(aa + f3(bb,cc,dd) + X[11] + 0x6d703ef3, 12) + ee; cc = RL(cc, 10);
        ee = RL(ee + f3(aa,bb,cc) + X[ 8] + 0x6d703ef3, 13) + dd; bb = RL(bb, 10);
        dd = RL(dd + f3(ee,aa,bb) + X[12] + 0x6d703ef3,  5) + cc; aa = RL(aa, 10);
        cc = RL(cc + f3(dd,ee,aa) + X[ 2] + 0x6d703ef3, 14) + bb; ee = RL(ee, 10);
        bb = RL(bb + f3(cc,dd,ee) + X[10] + 0x6d703ef3, 13) + aa; dd = RL(dd, 10);
        aa = RL(aa + f3(bb,cc,dd) + X[ 0] + 0x6d703ef3, 13) + ee; cc = RL(cc, 10);
        ee = RL(ee + f3(aa,bb,cc) + X[ 4] + 0x6d703ef3,  7) + dd; bb = RL(bb, 10);
        dd = RL(dd + f3(ee,aa,bb) + X[13] + 0x6d703ef3,  5) + cc; aa = RL(aa, 10);
        //
        // Rounds 48-63
        //
        // left
        c = RL(c + f4(d,e,a) + X[ 1] + 0x8f1bbcdc, 11) + b; e = RL(e, 10);
        b = RL(b + f4(c,d,e) + X[ 9] + 0x8f1bbcdc, 12) + a; d = RL(d, 10);
        a = RL(a + f4(b,c,d) + X[11] + 0x8f1bbcdc, 14) + e; c = RL(c, 10);
        e = RL(e + f4(a,b,c) + X[10] + 0x8f1bbcdc, 15) + d; b = RL(b, 10);
        d = RL(d + f4(e,a,b) + X[ 0] + 0x8f1bbcdc, 14) + c; a = RL(a, 10);
        c = RL(c + f4(d,e,a) + X[ 8] + 0x8f1bbcdc, 15) + b; e = RL(e, 10);
        b = RL(b + f4(c,d,e) + X[12] + 0x8f1bbcdc,  9) + a; d = RL(d, 10);
        a = RL(a + f4(b,c,d) + X[ 4] + 0x8f1bbcdc,  8) + e; c = RL(c, 10);
        e = RL(e + f4(a,b,c) + X[13] + 0x8f1bbcdc,  9) + d; b = RL(b, 10);
        d = RL(d + f4(e,a,b) + X[ 3] + 0x8f1bbcdc, 14) + c; a = RL(a, 10);
        c = RL(c + f4(d,e,a) + X[ 7] + 0x8f1bbcdc,  5) + b; e = RL(e, 10);
        b = RL(b + f4(c,d,e) + X[15] + 0x8f1bbcdc,  6) + a; d = RL(d, 10);
        a = RL(a + f4(b,c,d) + X[14] + 0x8f1bbcdc,  8) + e; c = RL(c, 10);
        e = RL(e + f4(a,b,c) + X[ 5] + 0x8f1bbcdc,  6) + d; b = RL(b, 10);
        d = RL(d + f4(e,a,b) + X[ 6] + 0x8f1bbcdc,  5) + c; a = RL(a, 10);
        c = RL(c + f4(d,e,a) + X[ 2] + 0x8f1bbcdc, 12) + b; e = RL(e, 10);

        // right
        cc = RL(cc + f2(dd,ee,aa) + X[ 8] + 0x7a6d76e9, 15) + bb; ee = RL(ee, 10);
        bb = RL(bb + f2(cc,dd,ee) + X[ 6] + 0x7a6d76e9,  5) + aa; dd = RL(dd, 10);
        aa = RL(aa + f2(bb,cc,dd) + X[ 4] + 0x7a6d76e9,  8) + ee; cc = RL(cc, 10);
        ee = RL(ee + f2(aa,bb,cc) + X[ 1] + 0x7a6d76e9, 11) + dd; bb = RL(bb, 10);
        dd = RL(dd + f2(ee,aa,bb) + X[ 3] + 0x7a6d76e9, 14) + cc; aa = RL(aa, 10);
        cc = RL(cc + f2(dd,ee,aa) + X[11] + 0x7a6d76e9, 14) + bb; ee = RL(ee, 10);
        bb = RL(bb + f2(cc,dd,ee) + X[15] + 0x7a6d76e9,  6) + aa; dd = RL(dd, 10);
        aa = RL(aa + f2(bb,cc,dd) + X[ 0] + 0x7a6d76e9, 14) + ee; cc = RL(cc, 10);
        ee = RL(ee + f2(aa,bb,cc) + X[ 5] + 0x7a6d76e9,  6) + dd; bb = RL(bb, 10);
        dd = RL(dd + f2(ee,aa,bb) + X[12] + 0x7a6d76e9,  9) + cc; aa = RL(aa, 10);
        cc = RL(cc + f2(dd,ee,aa) + X[ 2] + 0x7a6d76e9, 12) + bb; ee = RL(ee, 10);
        bb = RL(bb + f2(cc,dd,ee) + X[13] + 0x7a6d76e9,  9) + aa; dd = RL(dd, 10);
        aa = RL(aa + f2(bb,cc,dd) + X[ 9] + 0x7a6d76e9, 12) + ee; cc = RL(cc, 10);
        ee = RL(ee + f2(aa,bb,cc) + X[ 7] + 0x7a6d76e9,  5) + dd; bb = RL(bb, 10);
        dd = RL(dd + f2(ee,aa,bb) + X[10] + 0x7a6d76e9, 15) + cc; aa = RL(aa, 10);
        cc = RL(cc + f2(dd,ee,aa) + X[14] + 0x7a6d76e9,  8) + bb; ee = RL(ee, 10);
        //
        // Rounds 64-79
        //
        // left
        b = RL(b + f5(c,d,e) + X[ 4] + 0xa953fd4e,  9) + a; d = RL(d, 10);
        a = RL(a + f5(b,c,d) + X[ 0] + 0xa953fd4e, 15) + e; c = RL(c, 10);
        e = RL(e + f5(a,b,c) + X[ 5] + 0xa953fd4e,  5) + d; b = RL(b, 10);
        d = RL(d + f5(e,a,b) + X[ 9] + 0xa953fd4e, 11) + c; a = RL(a, 10);
        c = RL(c + f5(d,e,a) + X[ 7] + 0xa953fd4e,  6) + b; e = RL(e, 10);
        b = RL(b + f5(c,d,e) + X[12] + 0xa953fd4e,  8) + a; d = RL(d, 10);
        a = RL(a + f5(b,c,d) + X[ 2] + 0xa953fd4e, 13) + e; c = RL(c, 10);
        e = RL(e + f5(a,b,c) + X[10] + 0xa953fd4e, 12) + d; b = RL(b, 10);
        d = RL(d + f5(e,a,b) + X[14] + 0xa953fd4e,  5) + c; a = RL(a, 10);
        c = RL(c + f5(d,e,a) + X[ 1] + 0xa953fd4e, 12) + b; e = RL(e, 10);
        b = RL(b + f5(c,d,e) + X[ 3] + 0xa953fd4e, 13) + a; d = RL(d, 10);
        a = RL(a + f5(b,c,d) + X[ 8] + 0xa953fd4e, 14) + e; c = RL(c, 10);
        e = RL(e + f5(a,b,c) + X[11] + 0xa953fd4e, 11) + d; b = RL(b, 10);
        d = RL(d + f5(e,a,b) + X[ 6] + 0xa953fd4e,  8) + c; a = RL(a, 10);
        c = RL(c + f5(d,e,a) + X[15] + 0xa953fd4e,  5) + b; e = RL(e, 10);
        b = RL(b + f5(c,d,e) + X[13] + 0xa953fd4e,  6) + a; d = RL(d, 10);

        // right
        bb = RL(bb + f1(cc,dd,ee) + X[12],  8) + aa; dd = RL(dd, 10);
        aa = RL(aa + f1(bb,cc,dd) + X[15],  5) + ee; cc = RL(cc, 10);
        ee = RL(ee + f1(aa,bb,cc) + X[10], 12) + dd; bb = RL(bb, 10);
        dd = RL(dd + f1(ee,aa,bb) + X[ 4],  9) + cc; aa = RL(aa, 10);
        cc = RL(cc + f1(dd,ee,aa) + X[ 1], 12) + bb; ee = RL(ee, 10);
        bb = RL(bb + f1(cc,dd,ee) + X[ 5],  5) + aa; dd = RL(dd, 10);
        aa = RL(aa + f1(bb,cc,dd) + X[ 8], 14) + ee; cc = RL(cc, 10);
        ee = RL(ee + f1(aa,bb,cc) + X[ 7],  6) + dd; bb = RL(bb, 10);
        dd = RL(dd + f1(ee,aa,bb) + X[ 6],  8) + cc; aa = RL(aa, 10);
        cc = RL(cc + f1(dd,ee,aa) + X[ 2], 13) + bb; ee = RL(ee, 10);
        bb = RL(bb + f1(cc,dd,ee) + X[13],  6) + aa; dd = RL(dd, 10);
        aa = RL(aa + f1(bb,cc,dd) + X[14],  5) + ee; cc = RL(cc, 10);
        ee = RL(ee + f1(aa,bb,cc) + X[ 0], 15) + dd; bb = RL(bb, 10);
        dd = RL(dd + f1(ee,aa,bb) + X[ 3], 13) + cc; aa = RL(aa, 10);
        cc = RL(cc + f1(dd,ee,aa) + X[ 9], 11) + bb; ee = RL(ee, 10);
        bb = RL(bb + f1(cc,dd,ee) + X[11], 11) + aa; dd = RL(dd, 10);

        dd += c + H1;
        H1 = H2 + d + ee; H2 = H3 + e + aa;
        H3 = H4 + a + bb; H4 = H0 + b + cc; H0 = dd;
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
        // определить размер данных в битах
        long bitLength = ((byteCount + dataLen) << 3);
        
        // выделить буфер для дополнения
        byte[] buffer = new byte[blockSize]; buffer[dataLen] = (byte)0x80;
        
        // скопировать данные
        System.arraycopy(data, dataOff, buffer, 0, dataLen);

        // обработать дополненный блок
        if (dataLen >= 56) { update(buffer, 0);

            // обнулить обработанный блок
            for (int i = 0; i < 56; i++) buffer[i] = 0; 
        }
        // обработать размер 
        Convert.fromInt64(bitLength, ENDIAN, buffer, 56); update(buffer, 0);

        // извлечь хэш-значение
        Convert.fromInt32(H0, ENDIAN, buf, bufOff +  0); 
        Convert.fromInt32(H1, ENDIAN, buf, bufOff +  4); 
        Convert.fromInt32(H2, ENDIAN, buf, bufOff +  8); 
        Convert.fromInt32(H3, ENDIAN, buf, bufOff + 12); 
        Convert.fromInt32(H4, ENDIAN, buf, bufOff + 16); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тесты известного ответа
    ////////////////////////////////////////////////////////////////////////////
    public static void test(Hash hashAlgorithm) throws Exception
    {
        knownTest(hashAlgorithm, 1, 
            "", new byte[] { 
            (byte)0x9c, (byte)0x11, (byte)0x85, (byte)0xa5, 
            (byte)0xc5, (byte)0xe9, (byte)0xfc, (byte)0x54, 
            (byte)0x61, (byte)0x28, (byte)0x08, (byte)0x97, 
            (byte)0x7e, (byte)0xe8, (byte)0xf5, (byte)0x48, 
            (byte)0xb2, (byte)0x25, (byte)0x8d, (byte)0x31
        }); 
        knownTest(hashAlgorithm, 1, 
            "a", new byte[] { 
            (byte)0x0b, (byte)0xdc, (byte)0x9d, (byte)0x2d, 
            (byte)0x25, (byte)0x6b, (byte)0x3e, (byte)0xe9, 
            (byte)0xda, (byte)0xae, (byte)0x34, (byte)0x7b, 
            (byte)0xe6, (byte)0xf4, (byte)0xdc, (byte)0x83, 
            (byte)0x5a, (byte)0x46, (byte)0x7f, (byte)0xfe
        }); 
        knownTest(hashAlgorithm, 1, 
            "abc", new byte[] { 
            (byte)0x8e, (byte)0xb2, (byte)0x08, (byte)0xf7, 
            (byte)0xe0, (byte)0x5d, (byte)0x98, (byte)0x7a, 
            (byte)0x9b, (byte)0x04, (byte)0x4a, (byte)0x8e, 
            (byte)0x98, (byte)0xc6, (byte)0xb0, (byte)0x87, 
            (byte)0xf1, (byte)0x5a, (byte)0x0b, (byte)0xfc
        }); 
        knownTest(hashAlgorithm, 1, 
            "message digest", new byte[] { 
            (byte)0x5d, (byte)0x06, (byte)0x89, (byte)0xef, 
            (byte)0x49, (byte)0xd2, (byte)0xfa, (byte)0xe5, 
            (byte)0x72, (byte)0xb8, (byte)0x81, (byte)0xb1, 
            (byte)0x23, (byte)0xa8, (byte)0x5f, (byte)0xfa, 
            (byte)0x21, (byte)0x59, (byte)0x5f, (byte)0x36
        }); 
        knownTest(hashAlgorithm, 1, 
            "abcdefghijklmnopqrstuvwxyz", new byte[] { 
            (byte)0xf7, (byte)0x1c, (byte)0x27, (byte)0x10, 
            (byte)0x9c, (byte)0x69, (byte)0x2c, (byte)0x1b, 
            (byte)0x56, (byte)0xbb, (byte)0xdc, (byte)0xeb, 
            (byte)0x5b, (byte)0x9d, (byte)0x28, (byte)0x65, 
            (byte)0xb3, (byte)0x70, (byte)0x8d, (byte)0xbc
        }); 
        knownTest(hashAlgorithm, 1, 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + 
            "abcdefghijklmnopqrstuvwxyz0123456789", new byte[] { 
            (byte)0xb0, (byte)0xe2, (byte)0x0b, (byte)0x6e, 
            (byte)0x31, (byte)0x16, (byte)0x64, (byte)0x02, 
            (byte)0x86, (byte)0xed, (byte)0x3a, (byte)0x87, 
            (byte)0xa5, (byte)0x71, (byte)0x30, (byte)0x79, 
            (byte)0xb2, (byte)0x1f, (byte)0x51, (byte)0x89
        }); 
        knownTest(hashAlgorithm, 1, 
            "1234567890123456789012345678901234567890" + 
            "1234567890123456789012345678901234567890", new byte[] { 
            (byte)0x9b, (byte)0x75, (byte)0x2e, (byte)0x45, 
            (byte)0x57, (byte)0x3d, (byte)0x4b, (byte)0x39, 
            (byte)0xf4, (byte)0xdb, (byte)0xd3, (byte)0x32, 
            (byte)0x3c, (byte)0xab, (byte)0x82, (byte)0xbf, 
            (byte)0x63, (byte)0x32, (byte)0x6b, (byte)0xfb
        }); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // HMAC
    ////////////////////////////////////////////////////////////////////////////
    public static void testHMAC(Mac algorithm) throws Exception
    {
        int[] keySizes = algorithm.keyFactory().keySizes(); 
        
        if (KeySizes.contains(keySizes, 20))
        Mac.knownTest(algorithm, new byte[] { 
            (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
            (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
            (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
            (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
            (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b
        }, 1, "Hi There", new byte[] {
            (byte)0x24, (byte)0xcb, (byte)0x4b, (byte)0xd6, 
            (byte)0x7d, (byte)0x20, (byte)0xfc, (byte)0x1a, 
            (byte)0x5d, (byte)0x2e, (byte)0xd7, (byte)0x73, 
            (byte)0x2d, (byte)0xcc, (byte)0x39, (byte)0x37, 
            (byte)0x7f, (byte)0x0a, (byte)0x56, (byte)0x68
        }); 
        if (KeySizes.contains(keySizes, 4))
        Mac.knownTest(algorithm, "Jefe".getBytes("UTF-8"), 
            1, "what do ya want for nothing?", new byte[] {
            (byte)0xdd, (byte)0xa6, (byte)0xc0, (byte)0x21, 
            (byte)0x3a, (byte)0x48, (byte)0x5a, (byte)0x9e, 
            (byte)0x24, (byte)0xf4, (byte)0x74, (byte)0x20, 
            (byte)0x64, (byte)0xa7, (byte)0xf0, (byte)0x33, 
            (byte)0xb4, (byte)0x3c, (byte)0x40, (byte)0x69
            }); 
        if (KeySizes.contains(keySizes, 20))
        Mac.knownTest(algorithm, new byte[] { 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
            (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA 
        }, 50, new byte[] { (byte)0xDD }, new byte[] {
            (byte)0xb0, (byte)0xb1, (byte)0x05, (byte)0x36, 
            (byte)0x0d, (byte)0xe7, (byte)0x59, (byte)0x96, 
            (byte)0x0a, (byte)0xb4, (byte)0xf3, (byte)0x52, 
            (byte)0x98, (byte)0xe1, (byte)0x16, (byte)0xe2, 
            (byte)0x95, (byte)0xd8, (byte)0xe7, (byte)0xc1
        }); 
        if (KeySizes.contains(keySizes, 25))
        Mac.knownTest(algorithm, new byte[] { 
            (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
            (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, 
            (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, 
            (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10, 
            (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, 
            (byte)0x15, (byte)0x16, (byte)0x17, (byte)0x18, 
            (byte)0x19
        }, 50, new byte[] { (byte)0xCD }, new byte[] {
            (byte)0xd5, (byte)0xca, (byte)0x86, (byte)0x2f, 
            (byte)0x4d, (byte)0x21, (byte)0xd5, (byte)0xe6, 
            (byte)0x10, (byte)0xe1, (byte)0x8b, (byte)0x4c, 
            (byte)0xf1, (byte)0xbe, (byte)0xb9, (byte)0x7a, 
            (byte)0x43, (byte)0x65, (byte)0xec, (byte)0xf4        
        }); 
        if (KeySizes.contains(keySizes, 20))
        Mac.knownTest(algorithm, new byte[] { 
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c,
            (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c
        }, 1, "Test With Truncation", new byte[] {
            (byte)0x76, (byte)0x19, (byte)0x69, (byte)0x39, 
            (byte)0x78, (byte)0xf9, (byte)0x1d, (byte)0x90, 
            (byte)0x53, (byte)0x9a, (byte)0xe7, (byte)0x86, 
            (byte)0x50, (byte)0x0f, (byte)0xf3, (byte)0xd8, 
            (byte)0xe0, (byte)0x51, (byte)0x8e, (byte)0x39        
        }); 
        if (KeySizes.contains(keySizes, 80))
        Mac.knownTest(algorithm, new byte[] { 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
        }, 1, "Test Using Larger Than Block-Size Key - Hash Key First", new byte[] {
            (byte)0x64, (byte)0x66, (byte)0xca, (byte)0x07, 
            (byte)0xac, (byte)0x5e, (byte)0xac, (byte)0x29, 
            (byte)0xe1, (byte)0xbd, (byte)0x52, (byte)0x3e, 
            (byte)0x5a, (byte)0xda, (byte)0x76, (byte)0x05, 
            (byte)0xb7, (byte)0x91, (byte)0xfd, (byte)0x8b        
        }); 
        if (KeySizes.contains(keySizes, 80))
        Mac.knownTest(algorithm, new byte[] { 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
            (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
        }, 1, "Test Using Larger Than Block-Size Key and Larger " + 
            "Than One Block-Size Data", new byte[] {
            (byte)0x69, (byte)0xea, (byte)0x60, (byte)0x79, 
            (byte)0x8d, (byte)0x71, (byte)0x61, (byte)0x6c, 
            (byte)0xce, (byte)0x5f, (byte)0xd0, (byte)0x87, 
            (byte)0x1e, (byte)0x23, (byte)0x75, (byte)0x4c, 
            (byte)0xd7, (byte)0x5d, (byte)0x5a, (byte)0x0a
        }); 
    }
}
