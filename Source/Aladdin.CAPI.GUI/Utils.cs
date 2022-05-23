using System; 
using System.Collections.Generic; 
using System.Reflection; 
using System.ComponentModel;
using System.Drawing; 
using System.Drawing.Imaging; 
using System.Drawing.Drawing2D; 

namespace Aladdin.CAPI.GUI
{
    public static class Utils
    {
        ///////////////////////////////////////////////////////////////////////
        // Получить описание значения перечисления
        ///////////////////////////////////////////////////////////////////////
        public static string GetDescription<T>(T enumerationValue) where T : struct
        {
            // создать список значений
            List<String> parts = new List<String>(); 

            // получить тип значения 
            Type type = enumerationValue.GetType(); 

            // для всех значений из представления
            foreach (string part in enumerationValue.ToString().Split(','))
            {
                // получить описание значения
                string name = part.Trim(); MemberInfo[] memberInfo = type.GetMember(name);

                // проверить наличие описания значения
                if (memberInfo == null || memberInfo.Length == 0) parts.Add(name); 
                else {
                    // получить атрибуты значения
                    object[] attrs = memberInfo[0].GetCustomAttributes(
                        typeof(DescriptionAttribute), false
                    );
                    // проверить наличие атрибута
                    if (attrs == null || attrs.Length == 0) parts.Add(name); 
                    
                    // сохранить значение атрибута
                    else parts.Add(((DescriptionAttribute)attrs[0]).Description);
                }
            }
            // объединить части
            return String.Join(", ", parts.ToArray()); 
        }
        ///////////////////////////////////////////////////////////////////////
		// Выполнить масштабирование 
        ///////////////////////////////////////////////////////////////////////
        public static Bitmap ScaleImage(Image image, int thumbWidth, int thumbHeight)
        {
            // указать прямоугольную область
            Rectangle destRect = new Rectangle(0, 0, thumbWidth, thumbHeight); 

            // определить коэффициенты расширения 
            double xRatio = (double)image.Width  / thumbWidth;
            double yRatio = (double)image.Height / thumbHeight;

            // согласовать коэффициенты расширения 
            double ratioToResizeImage = System.Math.Max(xRatio, yRatio);

            // определить новый размер 
            int newWidth  = (int)System.Math.Floor(image.Width  / ratioToResizeImage);
            int newHeight = (int)System.Math.Floor(image.Height / ratioToResizeImage);

            // создать новую битовую карту
            Bitmap newImage = new Bitmap(newWidth, newHeight, PixelFormat.Format32bppArgb);

            // получить доступ к графическим операциям
            using (Graphics newGraphic = Graphics.FromImage(newImage))
            {
                using (ImageAttributes wrapMode = new ImageAttributes())
                {
                    wrapMode.SetWrapMode(WrapMode.TileFlipXY);
                    newGraphic.DrawImage(image, destRect, 0, 0, image.Width, image.Height, GraphicsUnit.Pixel, wrapMode);
                }
                // Set the background color to be transparent (can change this to any color)
                newGraphic.Clear(Color.Transparent);

                // Set the method of scaling to use -- HighQualityBicubic is said to have the best quality
                newGraphic.InterpolationMode = InterpolationMode.HighQualityBicubic;

                // Apply the transformation onto the new graphic
                Rectangle sourceDimensions      = new Rectangle(0, 0, image.Width, image.Height);
                Rectangle destinationDimensions = new Rectangle(0, 0, newWidth, newHeight);
                newGraphic.DrawImage(image, destinationDimensions, sourceDimensions, GraphicsUnit.Pixel);
            }
            return newImage;
        }

    }
}
