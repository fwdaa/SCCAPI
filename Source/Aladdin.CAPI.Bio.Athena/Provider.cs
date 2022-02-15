using System;
using System.IO;

namespace Aladdin.CAPI.Bio.Athena
{
    ///////////////////////////////////////////////////////////////////////////
    /// Реализация провайдера биометрии BiomatchFlex SDK
    ///////////////////////////////////////////////////////////////////////////
    public sealed class Provider : BSAPI.Provider
    {
        // биометрическое окружение
        private PreciseBiometrics.BMFH.BioMatch environment;
	
        // конструктор
        public Provider() { environment = new PreciseBiometrics.BMFH.BioMatch(); }

        // имя провайдера
        public override string Name { get { return "Athena Biometric Provider"; }}

		// создать изображение 
		public override Bio.Image CreateImage(byte[] content)
        {
    		// получаемое изображение
			PreciseBiometrics.BMFH.BM_Image bmImage; 

			// преобразовать формат файла
			environment.ImportImageFromBitmap(content, out bmImage);

		    // создать изображение 
            return new Image(environment, bmImage); 
        }
		// создать шаблон отпечатка для сравнения
        public override Bio.MatchTemplate CreateMatchTemplate(
            Finger finger, Bio.Image image, object publicData)
        {
            // извлечь внутренний объект
            PreciseBiometrics.BMFH.BM_Image imageBM = ((Image)image).Object; 
            
			// создать шаблон от открытых данных
            PreciseBiometrics.BMFH.BMFH_Template publicTemplate = 
				PreciseBiometrics.BMFH.BMFH_Template.BMFH_CreateBiometricHeaderTemplate(
                    (byte[])publicData
            );
			// создать шаблон отпечатка для сравнения
            PreciseBiometrics.BMFH.BMFH_Template verifyTemplate;
			PreciseBiometrics.BMFH.BM_ReturnCode result = 
				environment.CreateVerificationTemplateFromImage(
                    imageBM, publicTemplate, out verifyTemplate
            );
			// проверить отсутствие ошибок
			if (PreciseBiometrics.BMFH.BM_ReturnCode.Ok != result) throw new IOException();

			// вернуть бинарную форму шаблона для сравнения
            return new MatchTemplate(finger, verifyTemplate.ValidationData);  
        }
        // cоздать шаблон отпечатка для регистрации
        public override Bio.EnrollTemplate CreateEnrollTemplate(
            Finger finger, Bio.Image image, int far)
        {
			// указать значение FAR
			PreciseBiometrics.BMFH.BM_FarLevel rateBM = PreciseBiometrics.BMFH.BM_FarLevel.Far1000000; 
            
			// указать значение FAR
            if (far <=    100) rateBM = PreciseBiometrics.BMFH.BM_FarLevel.Far100    ; else 
            if (far <=   1000) rateBM = PreciseBiometrics.BMFH.BM_FarLevel.Far1000   ; else 
            if (far <=  10000) rateBM = PreciseBiometrics.BMFH.BM_FarLevel.Far10000  ; else 
            if (far <= 100000) rateBM = PreciseBiometrics.BMFH.BM_FarLevel.Far100000 ; 

            // извлечь внутренний объект
            PreciseBiometrics.BMFH.BM_Image imageBM = ((Image)image).Object; 

			// выполнить запись в журнал
            PreciseBiometrics.BMFH.BMFH_Template enrollTemplate; 

			// создать шаблон отпечатка для регистрации
			PreciseBiometrics.BMFH.BM_ReturnCode result = 
                environment.CreateEnrolTemplateFromImage(imageBM, rateBM, out enrollTemplate);

			// при ошибке выбросить исключение
            if (PreciseBiometrics.BMFH.BM_ReturnCode.Ok != result) throw new IOException();

			// вернуть шаблон отпечатка для регистрации
            return new EnrollTemplate(environment, finger, enrollTemplate);
        }
    }
}
