using System;

namespace Aladdin.CAPI.Bio.BSAPI
{
 	///////////////////////////////////////////////////////////////////////
	// Информация отпечатка
	///////////////////////////////////////////////////////////////////////
    public struct ImageInfo {				        
        public UInt32       BackgroundColor;		// фоновый цвет отпечатка
        public int          ReconstructionScore;    // качество реконструкции в процентах
        public int          ImageScore; 		    // качество изображения в процентах
        public ImageQuality Quality; 			    // качество отпечатка
        public byte[]       Bitmap;                 // изображение в формате .BMP
    };
}
