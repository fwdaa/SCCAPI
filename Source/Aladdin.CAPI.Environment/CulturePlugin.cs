using System; 
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Расширение криптографических культур
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public abstract class CulturePlugin : RefObject, IParametersFactory, PBE.IPBECultureFactory
    {
        // конструктор
        public CulturePlugin(PBE.PBEParameters pbeParameters)
        
            // сохранить переданные параметры
            { this.pbeParameters = pbeParameters; } private PBE.PBEParameters pbeParameters;

        // параметры шифрования по паролю
        public PBE.PBEParameters PBEParameters { get { return pbeParameters; }} 

        // параметры ключа
        public abstract IParameters GetParameters(IRand rand, string keyOID, KeyUsage keyUsage); 

        // криптографическая культура для PKCS12
        public abstract PBE.PBECulture GetCulture(object window, string keyOID);
    }
}
