using System;
using System.IO;
using System.Collections.Generic;
using System.Globalization;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Код страны и национальные данные (0x41)
    ///////////////////////////////////////////////////////////////////////////
    public class CountryIndicator : DataObject
    {
        // описание региона и дополнительные данные
        public readonly RegionInfo Region; public readonly byte[] Data;

        // конструктор раскодирования
        public CountryIndicator(byte[] content) : base(Authority.ISO7816, ISO7816.Tag.CountryIndicator, content)
        {
            // извлечь три цифры
            int[] digits = Encoding.DecodeDigits(3, content, 0); 
        
            // вычислить код страны
            int code = digits[0] * 100 + digits[1] * 10 + digits[2];

            // получить описание региона
            Region = CountryIndicator.GetRegionInfo(code); 
            
            // проверить отсутствие ошибок
            if (Region == null) throw new InvalidDataException();
            
            // выделить память для переменной
            Data = new byte[content.Length * 2 - 3]; Data[0] = (byte)(content[1] & 0xF); 

            // скопировать дополнительные данные
            for (int i = 2; i < content.Length; i++)
            {
                // скопировать дополнительные данные
                Data[2 * i - 3] = (byte)(content[i] >>  4);
                Data[2 * i - 2] = (byte)(content[i] & 0xF);
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Стандарт ISO 3166
        ///////////////////////////////////////////////////////////////////////
        private static readonly Dictionary<Int32 ,String> ISO3166 = new Dictionary<Int32 ,String>(); 
        static CountryIndicator()
        {
            ISO3166.Add(  4, "AF"/*"AFG"*/); ISO3166.Add(  8, "AL"/*"ALB"*/); ISO3166.Add( 10, "AQ"/*"ATA"*/); 
            ISO3166.Add( 12, "DZ"/*"DZA"*/); ISO3166.Add( 16, "AS"/*"ASM"*/); ISO3166.Add( 20, "AD"/*"AND"*/); 
            ISO3166.Add( 24, "AO"/*"AGO"*/); ISO3166.Add( 28, "AG"/*"ATG"*/); ISO3166.Add( 31, "AZ"/*"AZE"*/); 
            ISO3166.Add( 32, "AR"/*"ARG"*/); ISO3166.Add( 36, "AU"/*"AUS"*/); ISO3166.Add( 40, "AT"/*"AUT"*/); 
            ISO3166.Add( 44, "BS"/*"BHS"*/); ISO3166.Add( 48, "BH"/*"BHR"*/); ISO3166.Add( 50, "BD"/*"BGD"*/); 
            ISO3166.Add( 51, "AM"/*"ARM"*/); ISO3166.Add( 52, "BB"/*"BRB"*/); ISO3166.Add( 56, "BE"/*"BEL"*/); 
            ISO3166.Add( 60, "BM"/*"BMU"*/); ISO3166.Add( 64, "BT"/*"BTN"*/); ISO3166.Add( 68, "BO"/*"BOL"*/); 
            ISO3166.Add( 70, "BA"/*"BIH"*/); ISO3166.Add( 72, "BW"/*"BWA"*/); ISO3166.Add( 74, "BV"/*"BVT"*/); 
            ISO3166.Add( 76, "BR"/*"BRA"*/); ISO3166.Add( 86, "IO"/*"IOT"*/); ISO3166.Add( 84, "BZ"/*"BLZ"*/); 
            ISO3166.Add( 90, "SB"/*"SLB"*/); ISO3166.Add( 92, "VG"/*"VGB"*/); ISO3166.Add( 96, "BN"/*"BRN"*/); 
            ISO3166.Add(100, "BG"/*"BGR"*/); ISO3166.Add(104, "MM"/*"MMR"*/); ISO3166.Add(108, "BI"/*"BDI"*/); 
            ISO3166.Add(112, "BY"/*"BLR"*/); ISO3166.Add(116, "KH"/*"KHM"*/); ISO3166.Add(120, "CM"/*"CMR"*/); 
            ISO3166.Add(124, "CA"/*"CAN"*/); ISO3166.Add(132, "CV"/*"CPV"*/); ISO3166.Add(136, "KY"/*"CYM"*/); 
            ISO3166.Add(140, "CF"/*"CAF"*/); ISO3166.Add(144, "LK"/*"LKA"*/); ISO3166.Add(148, "TD"/*"TCD"*/); 
            ISO3166.Add(152, "CL"/*"CHL"*/); ISO3166.Add(156, "CN"/*"CHN"*/); ISO3166.Add(158, "TW"/*"TWN"*/); 
            ISO3166.Add(162, "CX"/*"CXR"*/); ISO3166.Add(166, "CC"/*"CCK"*/); ISO3166.Add(170, "CO"/*"COL"*/); 
            ISO3166.Add(174, "KM"/*"COM"*/); ISO3166.Add(175, "YT"/*"MYT"*/); ISO3166.Add(178, "CG"/*"COG"*/); 
            ISO3166.Add(180, "CD"/*"COD"*/); ISO3166.Add(184, "CK"/*"COK"*/); ISO3166.Add(188, "CR"/*"CRI"*/); 
            ISO3166.Add(191, "HR"/*"HRV"*/); ISO3166.Add(192, "CU"/*"CUB"*/); ISO3166.Add(196, "CY"/*"CYP"*/); 
            ISO3166.Add(203, "CZ"/*"CZE"*/); ISO3166.Add(204, "BJ"/*"BEN"*/); ISO3166.Add(208, "DK"/*"DNK"*/); 
            ISO3166.Add(212, "DM"/*"DMA"*/); ISO3166.Add(214, "DO"/*"DOM"*/); ISO3166.Add(218, "EC"/*"ECU"*/); 
            ISO3166.Add(222, "SV"/*"SLV"*/); ISO3166.Add(226, "GQ"/*"GNQ"*/); ISO3166.Add(231, "ET"/*"ETH"*/); 
            ISO3166.Add(232, "ER"/*"ERI"*/); ISO3166.Add(233, "EE"/*"EST"*/); ISO3166.Add(234, "FO"/*"FRO"*/); 
            ISO3166.Add(238, "FK"/*"FLK"*/); ISO3166.Add(239, "GS"/*"SGS"*/); ISO3166.Add(242, "FJ"/*"FJI"*/); 
            ISO3166.Add(246, "FI"/*"FIN"*/); ISO3166.Add(248, "AX"/*"ALA"*/); ISO3166.Add(250, "FR"/*"FRA"*/); 
            ISO3166.Add(254, "GF"/*"GUF"*/); ISO3166.Add(258, "PF"/*"PYF"*/); ISO3166.Add(260, "TF"/*"ATF"*/); 
            ISO3166.Add(262, "DJ"/*"DJI"*/); ISO3166.Add(266, "GA"/*"GAB"*/); ISO3166.Add(268, "GE"/*"GEO"*/); 
            ISO3166.Add(270, "GM"/*"GMB"*/); ISO3166.Add(275, "PS"/*"PSE"*/); ISO3166.Add(276, "DE"/*"DEU"*/); 
            ISO3166.Add(288, "GH"/*"GHA"*/); ISO3166.Add(292, "GI"/*"GIB"*/); ISO3166.Add(296, "KI"/*"KIR"*/); 
            ISO3166.Add(300, "GR"/*"GRC"*/); ISO3166.Add(304, "GL"/*"GRL"*/); ISO3166.Add(308, "GD"/*"GRD"*/); 
            ISO3166.Add(312, "GP"/*"GLP"*/); ISO3166.Add(316, "GU"/*"GUM"*/); ISO3166.Add(320, "GT"/*"GTM"*/); 
            ISO3166.Add(324, "GN"/*"GIN"*/); ISO3166.Add(328, "GY"/*"GUY"*/); ISO3166.Add(332, "HT"/*"HTI"*/); 
            ISO3166.Add(334, "HM"/*"HMD"*/); ISO3166.Add(336, "VA"/*"VAT"*/); ISO3166.Add(340, "HN"/*"HND"*/); 
            ISO3166.Add(344, "HK"/*"HKG"*/); ISO3166.Add(348, "HU"/*"HUN"*/); ISO3166.Add(352, "IS"/*"ISL"*/); 
            ISO3166.Add(356, "IN"/*"IND"*/); ISO3166.Add(360, "ID"/*"IDN"*/); ISO3166.Add(364, "IR"/*"IRN"*/); 
            ISO3166.Add(368, "IQ"/*"IRQ"*/); ISO3166.Add(372, "IE"/*"IRL"*/); ISO3166.Add(376, "IL"/*"ISR"*/); 
            ISO3166.Add(380, "IT"/*"ITA"*/); ISO3166.Add(384, "CI"/*"CIV"*/); ISO3166.Add(388, "JM"/*"JAM"*/); 
            ISO3166.Add(392, "JP"/*"JPN"*/); ISO3166.Add(398, "KZ"/*"KAZ"*/); ISO3166.Add(400, "JO"/*"JOR"*/); 
            ISO3166.Add(404, "KE"/*"KEN"*/); ISO3166.Add(408, "KP"/*"PRK"*/); ISO3166.Add(410, "KR"/*"KOR"*/); 
            ISO3166.Add(414, "KW"/*"KWT"*/); ISO3166.Add(417, "KG"/*"KGZ"*/); ISO3166.Add(418, "LA"/*"LAO"*/); 
            ISO3166.Add(422, "LB"/*"LBN"*/); ISO3166.Add(426, "LS"/*"LSO"*/); ISO3166.Add(428, "LV"/*"LVA"*/); 
            ISO3166.Add(430, "LR"/*"LBR"*/); ISO3166.Add(434, "LY"/*"LBY"*/); ISO3166.Add(438, "LI"/*"LIE"*/); 
            ISO3166.Add(440, "LT"/*"LTU"*/); ISO3166.Add(442, "LU"/*"LUX"*/); ISO3166.Add(446, "MO"/*"MAC"*/); 
            ISO3166.Add(450, "MG"/*"MDG"*/); ISO3166.Add(454, "MW"/*"MWI"*/); ISO3166.Add(458, "MY"/*"MYS"*/); 
            ISO3166.Add(462, "MV"/*"MDV"*/); ISO3166.Add(466, "ML"/*"MLI"*/); ISO3166.Add(470, "MT"/*"MLT"*/); 
            ISO3166.Add(474, "MQ"/*"MTQ"*/); ISO3166.Add(478, "MR"/*"MRT"*/); ISO3166.Add(480, "MU"/*"MUS"*/); 
            ISO3166.Add(484, "MX"/*"MEX"*/); ISO3166.Add(492, "MC"/*"MCO"*/); ISO3166.Add(496, "MN"/*"MNG"*/); 
            ISO3166.Add(498, "MD"/*"MDA"*/); ISO3166.Add(499, "ME"/*"MNE"*/); ISO3166.Add(500, "MS"/*"MSR"*/); 
            ISO3166.Add(504, "MA"/*"MAR"*/); ISO3166.Add(508, "MZ"/*"MOZ"*/); ISO3166.Add(512, "OM"/*"OMN"*/); 
            ISO3166.Add(516, "NA"/*"NAM"*/); ISO3166.Add(520, "NR"/*"NRU"*/); ISO3166.Add(524, "NP"/*"NPL"*/); 
            ISO3166.Add(528, "NL"/*"NLD"*/); ISO3166.Add(531, "CW"/*"CUW"*/); ISO3166.Add(533, "AW"/*"ABW"*/); 
            ISO3166.Add(534, "SX"/*"SXM"*/); ISO3166.Add(535, "BQ"/*"BES"*/); ISO3166.Add(540, "NC"/*"NCL"*/); 
            ISO3166.Add(548, "VU"/*"VUT"*/); ISO3166.Add(554, "NZ"/*"NZL"*/); ISO3166.Add(558, "NI"/*"NIC"*/); 
            ISO3166.Add(562, "NE"/*"NER"*/); ISO3166.Add(566, "NG"/*"NGA"*/); ISO3166.Add(570, "NU"/*"NIU"*/); 
            ISO3166.Add(574, "NF"/*"NFK"*/); ISO3166.Add(578, "NO"/*"NOR"*/); ISO3166.Add(580, "MP"/*"MNP"*/); 
            ISO3166.Add(581, "UM"/*"UMI"*/); ISO3166.Add(583, "FM"/*"FSM"*/); ISO3166.Add(584, "MH"/*"MHL"*/); 
            ISO3166.Add(585, "PW"/*"PLW"*/); ISO3166.Add(586, "PK"/*"PAK"*/); ISO3166.Add(591, "PA"/*"PAN"*/); 
            ISO3166.Add(598, "PG"/*"PNG"*/); ISO3166.Add(600, "PY"/*"PRY"*/); ISO3166.Add(604, "PE"/*"PER"*/); 
            ISO3166.Add(608, "PH"/*"PHL"*/); ISO3166.Add(612, "PN"/*"PCN"*/); ISO3166.Add(616, "PL"/*"POL"*/); 
            ISO3166.Add(620, "PT"/*"PRT"*/); ISO3166.Add(624, "GW"/*"GNB"*/); ISO3166.Add(626, "TL"/*"TLS"*/); 
            ISO3166.Add(630, "PR"/*"PRI"*/); ISO3166.Add(634, "QA"/*"QAT"*/); ISO3166.Add(638, "RE"/*"REU"*/); 
            ISO3166.Add(642, "RO"/*"ROU"*/); ISO3166.Add(643, "RU"/*"RUS"*/); ISO3166.Add(646, "RW"/*"RWA"*/); 
            ISO3166.Add(652, "BL"/*"BLM"*/); ISO3166.Add(654, "SH"/*"SHN"*/); ISO3166.Add(659, "KN"/*"KNA"*/); 
            ISO3166.Add(660, "AI"/*"AIA"*/); ISO3166.Add(662, "LC"/*"LCA"*/); ISO3166.Add(663, "MF"/*"MAF"*/); 
            ISO3166.Add(666, "PM"/*"SPM"*/); ISO3166.Add(670, "VC"/*"VCT"*/); ISO3166.Add(674, "SM"/*"SMR"*/); 
            ISO3166.Add(678, "ST"/*"STP"*/); ISO3166.Add(682, "SA"/*"SAU"*/); ISO3166.Add(686, "SN"/*"SEN"*/); 
            ISO3166.Add(688, "RS"/*"SRB"*/); ISO3166.Add(690, "SC"/*"SYC"*/); ISO3166.Add(694, "SL"/*"SLE"*/); 
            ISO3166.Add(702, "SG"/*"SGP"*/); ISO3166.Add(703, "SK"/*"SVK"*/); ISO3166.Add(704, "VN"/*"VNM"*/); 
            ISO3166.Add(705, "SI"/*"SVN"*/); ISO3166.Add(706, "SO"/*"SOM"*/); ISO3166.Add(710, "ZA"/*"ZAF"*/); 
            ISO3166.Add(716, "ZW"/*"ZWE"*/); ISO3166.Add(724, "ES"/*"ESP"*/); ISO3166.Add(728, "SS"/*"SSD"*/); 
            ISO3166.Add(729, "SD"/*"SDN"*/); ISO3166.Add(732, "EH"/*"ESH"*/); ISO3166.Add(740, "SR"/*"SUR"*/); 
            ISO3166.Add(744, "SJ"/*"SJM"*/); ISO3166.Add(748, "SZ"/*"SWZ"*/); ISO3166.Add(752, "SE"/*"SWE"*/); 
            ISO3166.Add(756, "CH"/*"CHE"*/); ISO3166.Add(760, "SY"/*"SYR"*/); ISO3166.Add(762, "TJ"/*"TJK"*/); 
            ISO3166.Add(764, "TH"/*"THA"*/); ISO3166.Add(768, "TG"/*"TGO"*/); ISO3166.Add(772, "TK"/*"TKL"*/); 
            ISO3166.Add(776, "TO"/*"TON"*/); ISO3166.Add(780, "TT"/*"TTO"*/); ISO3166.Add(784, "AE"/*"ARE"*/); 
            ISO3166.Add(788, "TN"/*"TUN"*/); ISO3166.Add(792, "TR"/*"TUR"*/); ISO3166.Add(795, "TM"/*"TKM"*/); 
            ISO3166.Add(796, "TC"/*"TCA"*/); ISO3166.Add(798, "TV"/*"TUV"*/); ISO3166.Add(800, "UG"/*"UGA"*/); 
            ISO3166.Add(804, "UA"/*"UKR"*/); ISO3166.Add(807, "MK"/*"MKD"*/); ISO3166.Add(818, "EG"/*"EGY"*/); 
            ISO3166.Add(826, "GB"/*"GBR"*/); ISO3166.Add(831, "GG"/*"GGY"*/); ISO3166.Add(832, "JE"/*"JEY"*/); 
            ISO3166.Add(833, "IM"/*"IMN"*/); ISO3166.Add(834, "TZ"/*"TZA"*/); ISO3166.Add(840, "US"/*"USA"*/); 
            ISO3166.Add(850, "VI"/*"VIR"*/); ISO3166.Add(854, "BF"/*"BFA"*/); ISO3166.Add(858, "UY"/*"URY"*/); 
            ISO3166.Add(860, "UZ"/*"UZB"*/); ISO3166.Add(862, "VE"/*"VEN"*/); ISO3166.Add(876, "WF"/*"WLF"*/); 
            ISO3166.Add(882, "WS"/*"WSM"*/); ISO3166.Add(887, "YE"/*"YEM"*/); ISO3166.Add(894, "ZM"/*"ZMB"*/); 
        }  
        public static RegionInfo GetRegionInfo(int code)
        {
            // проверить корректность кода страны
            if (!ISO3166.ContainsKey(code)) return null; 

            // получить описание региона
            return new RegionInfo(ISO3166[code]); 
        }
        public static int GetCountryCode(RegionInfo region)
        {
            // получить аббревиатеру страны
            string code = region.TwoLetterISORegionName; 

            // для всеъ элементов ISO 3166
            foreach (KeyValuePair<Int32, String> pair in ISO3166)
            {
                // проверить совпадение аббревиатуры
                if (pair.Value == code) return pair.Key; 
            }
            return -1; 
        }
    }
}
