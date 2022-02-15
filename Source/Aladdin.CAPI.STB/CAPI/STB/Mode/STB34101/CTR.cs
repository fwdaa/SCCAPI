namespace Aladdin.CAPI.STB.Mode.STB34101
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим CTR
    //////////////////////////////////////////////////////////////////////////////
    public class CTR : CAPI.Mode.CTR
    {
        // конструктор
	    public CTR(CAPI.Cipher engine, CipherMode.CTR mode) : base(engine, mode) {}

        // преобразование зашифрования
        protected override CAPI.Transform CreateEncryption(ISecretKey key) 
        { 
            // преобразовать тип параметров
            CipherMode.CTR parameters = (CipherMode.CTR)Mode; 

            // преобразование расшифрования
            return new CTR_ENC(Engine, key, parameters); 
        }
        // преобразование расшифрования
        protected override CAPI.Transform CreateDecryption(ISecretKey key) 
        { 
            // преобразовать тип параметров
            CipherMode.CTR parameters = (CipherMode.CTR)Mode; 

            // преобразование расшифрования
            return new CTR_ENC(Engine, key, parameters); 
        }
    }
}
