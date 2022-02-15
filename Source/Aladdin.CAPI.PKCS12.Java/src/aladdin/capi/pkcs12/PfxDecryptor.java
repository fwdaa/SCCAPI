package aladdin.capi.pkcs12;
import aladdin.asn1.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Расшифрование данных
///////////////////////////////////////////////////////////////////////////////
public interface PfxDecryptor 
{
    // расшифровать данные
	PfxData<byte[]> decrypt(byte[] data, 
        Class<? extends IEncodable> type) throws IOException; 
}
