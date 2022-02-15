#include "pch.h"

/* ************** Ошибка в реализации алгоритма ********************************

cms_pwri.c

176-178
-static int kek_unwrap_key(unsigned char *out, size_t *outlen,
-                          const unsigned char *in, size_t inlen,
-                          EVP_CIPHER_CTX *ctx)
+static int kek_unwrap_key(unsigned char *out, size_t *outlen,
+                          const unsigned char *in, size_t inlen,
+                          EVP_CIPHER_CTX *ctx, ASN1_TYPE* type)

209 
-        || !EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, NULL)
+	     || EVP_CIPHER_asn1_to_param(ctx, type) <= 0

369-371
-        if (!kek_unwrap_key(key, &keylen,
-                            pwri->encryptedKey->data,
-                            pwri->encryptedKey->length, kekctx)) {
+        if (!kek_unwrap_key(key, &keylen,
+                            pwri->encryptedKey->data,
+                            pwri->encryptedKey->length, kekctx, kekalg->parameter)) {

*******************************************************************************/
