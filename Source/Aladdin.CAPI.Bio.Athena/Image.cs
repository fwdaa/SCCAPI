using System;
using System.Drawing;

namespace Aladdin.CAPI.Bio.Athena
{
	///////////////////////////////////////////////////////////////////////////
    /// Изображение отпечатка Biomatch Flex
	///////////////////////////////////////////////////////////////////////////
    public class Image : Bio.Image
    {
		// изображение отпечатка
		private PreciseBiometrics.BMFH.BM_Image image; private int quality;

		// конструктор
        public Image(PreciseBiometrics.BMFH.BioMatch environment, 
			PreciseBiometrics.BMFH.BM_Image image)       
        {
			// сохранить переданные параметры
            this.image = image;  

			// указать выполняемые проверки
			PreciseBiometrics.BMFH.BM_StatusOption options = 
				PreciseBiometrics.BMFH.BM_StatusOption.Condition    | 
				PreciseBiometrics.BMFH.BM_StatusOption.Image        |
				PreciseBiometrics.BMFH.BM_StatusOption.Present      | 
				PreciseBiometrics.BMFH.BM_StatusOption.Quality;

			// проверить качество изображения
			environment.FingerStatus(image, out quality, out Condition, out Present, options);

			// проверить наличие отпечатка
			if (Present == PreciseBiometrics.BMFH.BM_ImagePresent.False) quality = 0; 
        }
        // внутренний объект
        public PreciseBiometrics.BMFH.BM_Image Object { get { return image; }}

		// результаты выполнения проверок
		public readonly PreciseBiometrics.BMFH.BM_ImageCondition Condition;
		public readonly PreciseBiometrics.BMFH.BM_ImagePresent   Present;

		// изображение для отображения 
        public override Object GetThumbnailImage(int thumbWidth, int thumbHeight) 
        { 
		    // изображение для отображения 
            return image.ToImage().GetThumbnailImage(thumbWidth, thumbHeight, null, IntPtr.Zero); 
        }
		// качество отпечатка
		public override int Quality { get { return quality; }}
    }
}
