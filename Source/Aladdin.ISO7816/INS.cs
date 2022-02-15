using System;

namespace Aladdin.ISO7816
{
///////////////////////////////////////////////////////////////////////////////
// Коды команд
///////////////////////////////////////////////////////////////////////////////
public static class INS 
{
	public const byte BERTLV                                = 0x01;
	public const byte DeactivateFile                        = 0x04;
	public const byte DeactivateRecord                      = 0x06;
	public const byte ActivateRecord                        = 0x08;
	public const byte EraseRecords                          = 0x0C;
	public const byte EraseBinary                           = 0x0E;
	public const byte EraseBinaryBERTLV                     = 0x0F;
	public const byte PerformSCQLOperation                  = 0x10;
	public const byte PerformTransactionOperation           = 0x12;
	public const byte PerformUserOperation                  = 0x14;
	public const byte Verify                                = 0x20;
	public const byte VerifyBERTLV                          = 0x21;
	public const byte ManageSecurityEnvironment             = 0x22;
	public const byte ChangeReferenceData                   = 0x24;
	public const byte ChangeReferenceDataBERTLV             = 0x25;
	public const byte DisableVerificationRequirement        = 0x26;
	public const byte EnableVerificationRequirement         = 0x28;
	public const byte PerformSecurityOperation              = 0x2A;
	public const byte PerformSecurityOperationBERTLV        = 0x2B;
	public const byte ResetRetryCounter                     = 0x2C;
	public const byte ResetRetryCounterBERTLV               = 0x2D;
	public const byte PerformBiometricOperation             = 0x2E;
	public const byte PerformBiometricOperationBERTLV       = 0x2F;
	public const byte CompareBERTLV                         = 0x33;
	public const byte GetAttribute                          = 0x34;
	public const byte GetAttributeBERTLV                    = 0x35;
	public const byte ApplicationManagementRequest          = 0x40;
	public const byte ApplicationManagementRequestBERTLV    = 0x41;
	public const byte ActivateFile                          = 0x44;
	public const byte GenerateAsymmetricKeyPair             = 0x46;
	public const byte GenerateAsymmetricKeyPairBERTLV       = 0x47;
	public const byte ManageChannel                         = 0x70;
	public const byte ExternalAuthenticate                  = 0x82;
	public const byte GetChallenge                          = 0x84;
	public const byte GeneralAuthenticate                   = 0x86;
	public const byte GeneralAuthenticateBERTLV             = 0x87;
	public const byte InternalAuthenticate                  = 0x88;
	public const byte SearchBinary                          = 0xA0;
	public const byte SearchBinaryBERTLV                    = 0xA1;
	public const byte SearchRecord                          = 0xA2;
	public const byte SearchRecordBERTLV                    = 0xA3;
	public const byte Select                                = 0xA4;
	public const byte SelectDataBERTLV                      = 0xA5;
	public const byte ReadBinary                            = 0xB0;
	public const byte ReadBinaryBERTLV                      = 0xB1;
	public const byte ReadRecords                           = 0xB2;
	public const byte ReadRecordsBERTLV                     = 0xB3;
	public const byte GetResponse                           = 0xC0;
	public const byte Envelope                              = 0xC2;
	public const byte EnvelopeBERTLV                        = 0xC3;
	public const byte GetData                               = 0xCA;
	public const byte GetDataBERTLV                         = 0xCB;
	public const byte GetNextData                           = 0xCC;
	public const byte GetNextDataBERTLV                     = 0xCD;
	public const byte ManageDataBERTLV                      = 0xCF;
	public const byte WriteBinary                           = 0xD0;
	public const byte WriteBinaryBERTLV                     = 0xD1;
	public const byte WriteRecord                           = 0xD2;
	public const byte UpdateBinary                          = 0xD6;
	public const byte UpdateBinaryBERTLV                    = 0xD7;
	public const byte PutNextData                           = 0xD8;
	public const byte PutNextDataBERTLV                     = 0xD9;
	public const byte PutData                               = 0xDA;
	public const byte PutDataBERTLV                         = 0xDB;
	public const byte UpdateRecord                          = 0xDC;
	public const byte UpdateRecordBERTLV                    = 0xDD;
	public const byte CreateFile                            = 0xE0;
	public const byte AppendRecord                          = 0xE2;
	public const byte DeleteFile                            = 0xE4;
	public const byte TerminateDF                           = 0xE6;
	public const byte TerminateEF                           = 0xE8;
	public const byte LoadApplication                       = 0xEA;
	public const byte LoadApplicationBERTLV                 = 0xEB;
	public const byte DeleteData                            = 0xEE;
	public const byte RemoveApplication                     = 0xEC;
	public const byte RemoveApplicationBERTLV               = 0xED;
	public const byte TerminateCardUsage                    = 0xFE;
}
}
