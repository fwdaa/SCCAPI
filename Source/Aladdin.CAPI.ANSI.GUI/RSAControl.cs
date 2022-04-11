﻿namespace Aladdin.CAPI.ANSI.GUI
{
    ///////////////////////////////////////////////////////////////////////////
    // Элемент управления выбора параметров ключа RSA
    ///////////////////////////////////////////////////////////////////////////
    public partial class RSAControl : CAPI.GUI.ParametersControl
    {
        // конструктор
        public RSAControl() { InitializeComponent(); }

		// получить параметры ключа
        public override IParameters GetParameters() 
        { 
            // вернуть параметры ключа
            if (radio512 .Checked) return new RSA.Parameters( 512); 
            if (radio1024.Checked) return new RSA.Parameters(1024); 
            if (radio1536.Checked) return new RSA.Parameters(1536); 
            if (radio2048.Checked) return new RSA.Parameters(2048); 
            if (radio3072.Checked) return new RSA.Parameters(3072); 
            if (radio4096.Checked) return new RSA.Parameters(4096); 

            return null; 
        } 
    }
}
