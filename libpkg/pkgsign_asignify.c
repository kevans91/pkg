/*-
 * Copyright (c) 2021 Kyle Evans <kevans@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/stat.h>
#include <sys/param.h>
#include <sys/uio.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include <asignify.h>

#include "pkg.h"
#include "private/event.h"
#include "private/pkg.h"
#include "private/pkgsign.h"

struct asignify_ctx {
	struct pkgsign_ctx sctx;
};

/* Grab the ossl context from a pkgsign_ctx. */
#define	ASIGNIFY_CTX(c)	((struct asignify_ctx *)(c))

#if 0
static int
_load_private_key(struct asignify_ctx *keyinfo)
{
	FILE *fp;

	if ((fp = fopen(keyinfo->sctx.path, "re")) == NULL)
		return (EPKG_FATAL);

	keyinfo->key = PEM_read_PrivateKey(fp, 0, keyinfo->sctx.pw_cb,
	    keyinfo->sctx.path);
	if (keyinfo->key == NULL) {
		fclose(fp);
		return (EPKG_FATAL);
	}

	fclose(fp);

	if (EVP_PKEY_id(keyinfo->key) != keyinfo->sprof->keyid) {
		keyinfo->key = NULL;
		return (EPKG_FATAL);
	}

	return (EPKG_OK);
}

static EVP_PKEY *
_load_public_key_buf(const asignify_signer_profile_t *sprof, unsigned char *cert,
    int certlen)
{
	EVP_PKEY *pkey;
	BIO *bp;
	char errbuf[1024];

	bp = BIO_new_mem_buf((void *)cert, certlen);
	if (bp == NULL) {
		pkg_emit_error("error allocating public key bio: %s",
		    ERR_error_string(ERR_get_error(), errbuf));
		return (NULL);
	}

	pkey = PEM_read_bio_PUBKEY(bp, NULL, NULL, NULL);
	if (pkey == NULL) {
		pkg_emit_error("error reading public key: %s",
		    ERR_error_string(ERR_get_error(), errbuf));
		BIO_free(bp);
		return (NULL);
	}

	BIO_free(bp);

	if (EVP_PKEY_id(pkey) != sprof->keyid) {
		EVP_PKEY_free(pkey);
		pkg_emit_error("wrong key type, wanted '%s'", sprof->name);
		return (NULL);
	}

	return (pkey);
}
#endif

struct asignify_verify_cbdata {
	asignify_verify_t *actx;
	unsigned char *sig;
	size_t siglen;
};

static int
asignify_verify_internal(asignify_verify_t *actx, unsigned char *sig,
    size_t siglen)
{
	char *blake2;
	int ret;

	blake2 = pkg_checksum_fd(fd, PKG_HASH_TYPE_BLAKE2_RAW);
	if (blake2 == NULL) {
		return (EPKG_FATAL);
	}


	ret = RSA_verify(nid, hash, pkg_checksum_type_size(ctype),
	    sig, siglen, rsa);

	RSA_free(rsa);

	/* Translate to rough equivalent; error string has something. */
	if (ret == 0)
		ret = -1;
#endif
	return (ret);
}

static int
asignify_verify_cert_cb(int fd, void *ud)
{
	struct asignify_verify_cbdata *cbdata = ud;
	char *sha256;
	char *hash;
	const asignify_signer_profile_t *sprof = cbdata->sprof;
	char errbuf[1024];
	EVP_PKEY *pkey = NULL;
	int ret;

	sha256 = pkg_checksum_fd(fd, PKG_HASH_TYPE_SHA256_HEX);
	if (sha256 == NULL)
		return (EPKG_FATAL);

	hash = pkg_checksum_data(sha256, strlen(sha256), sprof->cert_hash);
	free(sha256);

	pkey = _load_public_key_buf(cbdata->sprof, cbdata->key, cbdata->keylen);
	if (pkey == NULL) {
		free(hash);
		return (EPKG_FATAL);
	}

	ret = asignify_verify_internal(sprof, pkey, hash, cbdata->sig,
	    cbdata->siglen, sprof->cert_hash,
	    asignify_profile_digest(sprof, sprof->cert_hash));

	EVP_PKEY_free(pkey);
	free(hash);
	if (ret <= 0) {
		if (ret < 0)
			pkg_emit_error("rsa verify failed: %s",
			    ERR_error_string(ERR_get_error(), errbuf));
		else
			pkg_emit_error("rsa signature verification failure");
		return (EPKG_FATAL);
	}

	return (EPKG_OK);
}

static int
asignify_verify_cert(struct pkgsign_ctx *sctx, unsigned char *key,
    size_t keylen, unsigned char *sig, size_t siglen, int fd)
{
	struct asignify_verify_cbdata cbdata;
	struct asignify_ctx *keyinfo = ASIGNIFY_CTX(sctx);
	int ret;

	(void)lseek(fd, 0, SEEK_SET);

	cbdata.sprof = keyinfo->sprof;
	cbdata.key = key;
	cbdata.keylen = keylen;
	cbdata.sig = sig;
	cbdata.siglen = siglen;

	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();

	ret = pkg_emit_sandbox_call(asignify_verify_cert_cb, fd, &cbdata);
	if (need_close)
		close(fd);

	return (ret);
}

static int
asignify_verify_cb(int fd, void *ud)
{
	struct asignify_verify_cbdata *cbdata = ud;

	return (asignify_verify_internal(actx, cbdata->sig, cbdata->siglen));
}

static int
asignify_verify(struct pkgsign_ctx *sctx, const char *keypath,
    unsigned char *sig, size_t sig_len, int fd)
{
	int ret;
	asignify_verify_t *actx;
	struct asignify_verify_cbdata cbdata;
	char *key_buf;
	off_t key_len;

	actx = asignify_verify_init();
	if (actx == NULL) {
		pkg_emit_error("failed to initialize asignify context");
		return (EPKG_FATAL);
	}

	if (!asignify_verify_load_pubkey(actx, keypath)) {
		pkg_emit_error("failed to setup pubkey context");
		asignify_verify_free(actx);
		return (EPKG_FATAL);
	}

	(void)lseek(fd, 0, SEEK_SET);

	cbdata.actx = ctx;
	cbdata.sig = sig;
	cbdata.siglen = sig_len;

	ret = pkg_emit_sandbox_call(asignify_verify_cb, fd, &cbdata);

	return (ret);
}

static int
asignify_pw_cb_bridge(char *buf, size_t len, void *data)
{
	struct pkgsign_ctx *sctx;

	sctx = data;
	return ((*sctx->pw_cb)(buf, len, 0, NULL));
}

static int
asignify_sign(struct pkgsign_ctx *sctx, char *path, unsigned char **sigret,
    size_t *siglen)
{
	int ret = EPKG_FATAL;
	asignify_sign_t *signctx;

	signctx = asignify_ign_init();
	if (signctx == NULL) {
		pkg_emit_error("failed to initialize asignify context");
		return (EPKG_FATAL);
	}

	if (!asignify_sign_load_privkey(signctx, sctx->path, asignify_pw_cb_bridge,
	    sctx)) {
		pkg_emit_error("failed to load private key: %s",
		    asignify_sign_get_error(signctx));
		goto out;
	}

	if (!asignify_sign_add_file(signctx, path, ASIGNIFY_DIGEST_BLAKE2)) {
		pkg_emit_error("failed to add file for hashing: %s",
		    asignify_sign_get_error(sctx));
		goto out;
	}

	if (!asignify_sign_write_signature(signctx, NULL /* XXX */)) {

	}
out:
	asignify_ign_free(signctx);
	return (ret);

#if 0
	char errbuf[1024];
	struct asignify_ctx *keyinfo = ASIGNIFY_CTX(sctx);
	const asignify_signer_profile_t *sprof = keyinfo->sprof;
	int max_len = 0, ret;
	char *sha256;

	/* We only support raw providers for now. */
	assert((sprof->pflags & PFLAG_RAW) != 0);
	if (access(keyinfo->sctx.path, R_OK) == -1) {
		pkg_emit_errno("access", keyinfo->sctx.path);
		return (EPKG_FATAL);
	}

	if (keyinfo->key == NULL && _load_private_key(keyinfo) != EPKG_OK) {
		pkg_emit_error("can't load key from %s", keyinfo->sctx.path);
		return (EPKG_FATAL);
	}

	max_len = EVP_PKEY_size(keyinfo->key);
	*sigret = xcalloc(1, max_len + 1);

	sha256 = pkg_checksum_file(path, sprof->hash);
	if (sha256 == NULL)
		return (EPKG_FATAL);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	ctx = EVP_PKEY_CTX_new(keyinfo->key, NULL);
	if (ctx == NULL) {
		free(sha256);
		return (EPKG_FATAL);
	}

	if (EVP_PKEY_sign_init(ctx) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		free(sha256);
		return (EPKG_FATAL);
	}

	if ((sprof->pflags & PFLAG_RSA) != 0 &&
	    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		free(sha256);
		return (EPKG_FATAL);
	}

	if (EVP_PKEY_CTX_set_signature_md(ctx,
	    asignify_profile_digest(sprof, sprof->hash)) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		free(sha256);
		return (EPKG_FATAL);
	}

	*siglen = max_len;
	ret = EVP_PKEY_sign(ctx, *sigret, siglen, sha256,
	    pkg_checksum_type_size(sprof->hash));

	EVP_PKEY_CTX_free(ctx);
#else
	rsa = EVP_PKEY_get1_RSA(keyinfo->key);

	ret = RSA_sign(NID_sha1, sha256,
	    pkg_checksum_type_size(sprof->hash), *sigret, &ssiglen, rsa);

	RSA_free(rsa);
#endif
	free(sha256);
	if (ret <= 0) {
		pkg_emit_error("%s: %s", keyinfo->sctx.path,
		   ERR_error_string(ERR_get_error(), errbuf));
		return (EPKG_FATAL);
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	*siglen = ssiglen;
#endif

	return (EPKG_OK);
#endif
}
#endif

static bool
asignify_parse_rounds(const char *str, long *rounds)
{
	char *endp;
	long val;

	if (*str == '\0')
		return (false);
	errno = 0;
	val = strtol(str, &endp, 10);
	if (*endp == '\0' || errno != 0)
		return (false);
	if (val < 0)
		return (false);
	*rounds = val;
	return (true);
}

/*
 * asignify key generation; accepts the following parameters via iov:
 * - encrypted: (yes|YES) -> encrypt the key
 * - rounds: (num > PBKDF_MINROUNDS) -> # pbkdf rounds, default == min * 10
 */
static int
asignify_generate_key(struct pkgsign_ctx *sctx, const struct iovec *iov,
    int niov)
{
	char *keytmp, *pubpath, *pubtmp, *val;
	long rounds;
	int rc;
	bool encrypted;

	rounds = -1;
	encrypted = false;
	if (niov > 0) {
		for (int i = 0; i < niov; i += 2) {
			val = iov[i + 1].iov_base;
			if (strcmp(iov[i].iov_base, "encrypted") == 0) {
				encrypted = strcasecmp(val, "yes") == 0;
			} else if (strcmp(iov[i].iov_base, "rounds") == 0) {
				if (!asignify_parse_rounds(val, &rounds)) {
					pkg_emit_error("invalid # rounds: %s",
					    val);
					return (EPKG_FATAL);
				}
				if (rounds < PBKDF_MINROUNDS) {
					pkg_emit_error("minimum rounds (%d) not met by %lu",
					    PBKDF_MINROUNDS, rounds);
					return (EPKG_FATAL);
				}

				encrypted = true;
			}
		}
	}

	if (rounds < 0)
		rounds = (encrypted ? PBKDF_MINROUNDS * 10 : 0);

	xasprintf(&keytmp, "%s.XXXXXXXX", sctx->path);
	xasprintf(&pubpath, "%s.pub", sctx->path);
	xasprintf(&pubtmp, "%s.XXXXXXXX", pubpath);

	if (mktemp(keytmp) == NULL) {
		pkg_emit_error("failed to create temp file '%s'", keytmp);
		rc = EPKG_FATAL;
		goto out;
	}

	if (mktemp(pubtmp) == NULL) {
		unlink(keytmp);
		pkg_emit_error("failed to create temp file '%s'", pubtmp);
		rc = EPKG_FATAL;
		goto out;
	}

	if (!asignify_generate(keytmp, pubtmp, 1, rounds,
	    rounds == 0 ? NULL : asignify_pw_cb_bridge, sctx)) {
		unlink(keytmp);
		unlink(pubtmp);
		pkg_emit_error("failed to generate keypair\n");
		rc = EPKG_FATAL;
		goto out;
	}

	rc = rename(pubtmp, pubpath);
	if (rc != 0) {
		/* XXX Failed pubkey move. */
		unlink(pubtmp);
		rc = EPKG_FATAL;
		goto out;
	}

	rc = rename(keytmp, sctx->path);
	if (rc != 0) {
		/* XXX Failed pubkey move. */
		unlink(keytmp);
		/* Pubkey is worthless now... */
		unlink(pubpath);
		rc = EPKG_FATAL;
		goto out;
	}

out:
	free(keytmp);
	free(pubpath);
	free(pubtmp);
	return (rc);
}

static int
asignify_pubkey(struct pkgsign_ctx *sctx, FILE *fp)
{
	int fd;

	fd = fileno(fp);
	if (fd == -1) {
		pkg_emit_error("unusable output stream");
		return (EPKG_FATAL);
	}

	if (!asignify_write_pubkey(sctx->path, fd, asignify_pw_cb_bridge,
	    sctx)) {
		pkg_emit_error("failed to write public key");
		return (EPKG_FATAL);
	}

	return (EPKG_OK);
}

#if 0
static int
asignify_keyinfo(struct pkgsign_ctx *sctx, struct iovec **iov, int *niov)
{
	struct asignify_ctx *keyinfo = ASIGNIFY_CTX(sctx);
	RSA *rsa;
	struct iovec *piov;
	int bits, cnt;

	assert(*iov == NULL);
	if (keyinfo->key == NULL && _load_private_key(keyinfo) != EPKG_OK) {
		pkg_emit_error("can't load key from %s", keyinfo->sctx.path);
		return (EPKG_FATAL);
	}

	rsa = EVP_PKEY_get1_RSA(keyinfo->key);
	cnt = 2;	/* Bits */

	piov = xcalloc(cnt, sizeof(*piov));
	*iov = piov;
	*niov = cnt;

#define	IOV_KEY(elem, str) do {		\
	(elem).iov_base = str;		\
	(elem).iov_len = sizeof(str);	\
} while (0);

	IOV_KEY(piov[0], "bits");

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	bits = RSA_bits(rsa);
#else
	bits = RSA_size(rsa) * 8;
#endif
	piov[1].iov_len = xasprintf((char **)&piov[1].iov_base, "%d", bits);

	RSA_free(rsa);

	return (EPKG_OK);
}
#endif

const struct pkgsign_ops pkgsign_asignify = {
	.pkgsign_ctx_size = sizeof(struct asignify_ctx),

	.pkgsign_sign = asignify_sign,
	.pkgsign_verify = asignify_verify,
	.pkgsign_verify_cert = asignify_verify_cert,

	.pkgsign_generate = asignify_generate_key,
	.pkgsign_pubkey = asignify_pubkey,
#if notyet
	.pkgsign_keyinfo = asignify_keyinfo,
#endif
};
