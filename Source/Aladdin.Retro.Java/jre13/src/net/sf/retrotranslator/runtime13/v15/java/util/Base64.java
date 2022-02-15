package net.sf.retrotranslator.runtime13.v15.java.util;

public class Base64 
{
	private static final char[] MAP1 = new char[ 64];
	private static final byte[] MAP2 = new byte[128];
	static { 
		int i = 0;
		for (char c = 'A'; c <= 'Z'; c++) MAP1[i++] = c;
		for (char c = 'a'; c <= 'z'; c++) MAP1[i++] = c;
		for (char c = '0'; c <= '9'; c++) MAP1[i++] = c;
		MAP1[i++] = '+'; MAP1[i++] = '/';

    	for (i = 0; i < MAP2.length; i++) MAP2[i] = -1;
		for (i = 0; i < MAP1.length; i++) MAP2[MAP1[i]] = (byte)i;
    }
    public static Encoder getEncoder() { return new Encoder(); }
    public static Decoder getDecoder() { return new Decoder(); }
    
    // конструктор
    private Base64() {}
        
    ///////////////////////////////////////////////////////////////////////////
    // Закодирование данных
    ///////////////////////////////////////////////////////////////////////////
    public static class Encoder
    {
        // конструктор
        private Encoder() {}
        
        // закодировать данные
        public final String	encodeToString(byte[] in)
        {
            // закодировать данные
            return encodeToString(in, 0, in.length); 
        }
        // закодировать данные
        public final String	encodeToString(byte[] in, int off, int iLen)
        {
            int oLen   = ((iLen + 2) / 3) * 4;
            char[] out = new char[oLen];

            int oDataLen = (iLen * 4 + 2) / 3;
            int ip = off; int op = 0;
            while (ip < iLen)
            {
                int i0 = in[ip++] & 0xff;
                int i1 = ip < iLen ? in[ip++] & 0xff : 0;
                int i2 = ip < iLen ? in[ip++] & 0xff : 0;

                int o0 = i0 >>> 2;
                int o1 = ((i0 & 0x3) << 4) | (i1 >>> 4);
                int o2 = ((i1 & 0xf) << 2) | (i2 >>> 6);
                int o3 = i2 & 0x3F;

                out[op++] = MAP1[o0];
                out[op++] = MAP1[o1];
                out[op] = op < oDataLen ? MAP1[o2] : '='; op++;
                out[op] = op < oDataLen ? MAP1[o3] : '='; op++;
            }
            return String.valueOf(out);
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Раскодирование данных
    ///////////////////////////////////////////////////////////////////////////
    public static class Decoder
    {
        // конструктор
        private Decoder() {}
        
        // раскодировать данные
        public final byte[] decode(String s)
        {
            char[] in = s.toCharArray(); int iLen = in.length;
            if (iLen % 4 != 0) throw new IllegalArgumentException();

            while (iLen > 0 && in[iLen - 1] == '=') iLen--;
            int oLen = (iLen * 3) / 4;
            byte[] out = new byte[oLen];

            int ip = 0; int op = 0;
            while (ip < iLen)
            {
                int i0 = in[ip++]; if (i0 > 127) throw new IllegalArgumentException();
                int i1 = in[ip++]; if (i1 > 127) throw new IllegalArgumentException();
                
                int i2 = ip < iLen ? in[ip++] : 'A'; if (i2 > 127)
                {
                    throw new IllegalArgumentException();
                }
                int i3 = ip < iLen ? in[ip++] : 'A'; if (i3 > 127) 
                {
                    throw new IllegalArgumentException();
                }
                int b0 = MAP2[i0]; if (b0 < 0) throw new IllegalArgumentException();
                int b1 = MAP2[i1]; if (b1 < 0) throw new IllegalArgumentException();
                int b2 = MAP2[i2]; if (b2 < 0) throw new IllegalArgumentException();
                int b3 = MAP2[i3]; if (b3 < 0) throw new IllegalArgumentException();

                int o0 = ( b0        << 2) | (b1 >>> 4);
                int o1 = ((b1 & 0xf) << 4) | (b2 >>> 2);
                int o2 = ((b2 & 0x3) << 6) |  b3;

                out[op++] = (byte)o0;
                if (op<oLen) out[op++] = (byte)o1;
                if (op<oLen) out[op++] = (byte)o2;
            }
            return out;
        }
    }
}
