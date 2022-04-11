using System;

namespace Aladdin.CAPI.PBE
{
    ///////////////////////////////////////////////////////////////////////////
    // Параметры шифрования по паролю
    ///////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class PBEParameters
    {
        // размер salt-значения и число итераций
        private int pbmSaltLength; private int pbmIterations; 
        private int pbeSaltLength; private int pbeIterations; 

        // конструктор
        public PBEParameters(int pbmSaltLength, int pbmIterations, int pbeSaltLength, int pbeIterations)
        {
            // сохранить переданные параметры
            this.pbmSaltLength = pbmSaltLength; this.pbmIterations = pbmIterations; 
            this.pbeSaltLength = pbeSaltLength; this.pbeIterations = pbeIterations; 
        }
        // размер salt-значения и число итераций
        public int PBMSaltLength { get { return pbmSaltLength; }}
        public int PBMIterations { get { return pbmIterations; }}
        public int PBESaltLength { get { return pbeSaltLength; }}
        public int PBEIterations { get { return pbeIterations; }}
    }
}
