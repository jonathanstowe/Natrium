use v6;

use NativeCall :TEST, :DEFAULT;

use NativeHelpers::Array;

use LibraryCheck;


class Natrium {

    my Str $lib;
    sub find-lib-version() {
        $lib //= do {
            my Str $name = 'sodium';
            my Int $lower = 18;
            my Int $upper = 23;

            my $lib;

            for $lower .. $upper -> $version-number {
                my $version = Version.new($version-number);

                if library-exists($name, $version) {
                    $lib =  guess_library_name($name, $version) ;
                    last;
                }
            }
            $lib;
        }
    }

    constant LIB =  &find-lib-version;

    sub sodium_init() is native(LIB) returns int32 { * }

    class X::Init is Exception {
        has Str $.message = "failed to initialise crypto system";
    }

    submethod BUILD() {
        if sodium_init() < 0 {
            X::Init.new.throw;
        }
    }

    sub crypto_generichash_bytes() is native(LIB) returns size_t { * }

    has Int $.generichash-bytes;

    method generichash-bytes( --> Int ) {
        $!generichash-bytes //= crypto_generichash_bytes();
    }

    #-From /usr/include/sodium/crypto_generichash.h:49
    #SODIUM_EXPORT
    #int crypto_generichash(unsigned char *out, size_t outlen,
    sub crypto_generichash(CArray[uint8] $out, size_t $outlen, CArray[uint8] $in, ulonglong $inlen, CArray[uint8] $key, size_t $keylen --> int32 ) is native(LIB) { * }

    proto method generichash(|c) { * }

    multi method generichash(Blob $in --> Buf) {
        my CArray $out = CArray[uint8].new((0 xx self.generichash-bytes));
        my CArray $in-array = copy-buf-to-carray(Buf.new($in.list));
        crypto_generichash($out, self.generichash-bytes, $in-array, $in.elems, CArray[uint8], 0);
        copy-carray-to-buf($out, self.generichash-bytes)
    }

    multi method generichash(Str $in --> Buf ) {
        self.generichash($in.encode);
    }



    sub randombytes_random( --> uint32 ) is native(LIB) { * }

    proto method randombytes(|c) { * }

    multi method randombytes( --> Int ) {
        randombytes_random();
    }

    sub randombytes_uniform(uint32 $upper_bound --> uint32) is native(LIB) { * }

    multi method randombytes(Int :$upper-bound! --> Int ) {
        randombytes_uniform($upper-bound);
    }

    sub randombytes_buf(CArray[uint8] $buf, size_t $size) is native(LIB)  { * }

    multi method randombytes(Int :$buf! --> Buf ) {
        my CArray $data = CArray[uint8].new((0 xx $buf));
        randombytes_buf($data, $buf);
        copy-carray-to-buf($data, $buf);
    }


    #-From /usr/include/sodium/randombytes.h:38
    #SODIUM_EXPORT
    #void randombytes_stir(void);
    sub randombytes_stir(
                         ) is native(LIB)  { * }

    #-From /usr/include/sodium/randombytes.h:41
    #SODIUM_EXPORT
    #int randombytes_close(void);
    sub randombytes_close(
                          ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/randombytes.h:52
    #SODIUM_EXPORT
    #void randombytes(unsigned char * const buf, const unsigned long long buf_len);
    sub randombytes(CArray[uint8]                $buf # const unsigned char*
                   ,ulonglong                     $buf_len # const long long unsigned int
                    ) is native(LIB)  { * }

    class crypto_hash_sha256_state is repr('CStruct') {
        has CArray[uint32]              $.state; # Typedef<uint32>->|unsigned int|[8] state
        has uint64                      $.count; # Typedef<uint64>->|long unsigned int| count
        has CArray[uint8]                 $.buf; # unsigned char[64] buf
    }

    # == /usr/include/sodium/crypto_hash_sha512.h ==

    class crypto_hash_sha512_state is repr('CStruct') {
        has CArray[uint64]              $.state; # Typedef<uint64>->|long unsigned int|[8] state
        has CArray[uint64]              $.count; # Typedef<uint64>->|long unsigned int|[2] count
        has CArray[uint8]                 $.buf; # unsigned char[128] buf
    }

    class crypto_auth_hmacsha512_state is repr('CStruct') {
        has crypto_hash_sha512_state      $.ictx; # Typedef<crypto_hash_sha512_state>->|crypto_hash_sha512_state| ictx
        has crypto_hash_sha512_state      $.octx; # Typedef<crypto_hash_sha512_state>->|crypto_hash_sha512_state| octx
    }

    # == /usr/include/sodium/crypto_onetimeauth_poly1305.h ==

    class crypto_onetimeauth_poly1305_state is repr('CStruct') {
        has CArray[uint8]                 $.opaque; # unsigned char[256] opaque
    }

    # == /usr/include/sodium/crypto_generichash_blake2b.h ==

    class crypto_generichash_blake2b_state is repr('CStruct') {
        has CArray[uint64]              $.h; # Typedef<uint64>->|long unsigned int|[8] h
        has CArray[uint64]              $.t; # Typedef<uint64>->|long unsigned int|[2] t
        has CArray[uint64]              $.f; # Typedef<uint64>->|long unsigned int|[2] f
        has CArray[uint8]               $.buf; # Typedef<uint8>->|unsigned char|[256] buf
        has size_t                        $.buflen; # Typedef<size_t>->|long unsigned int| buflen
        has uint8                       $.last_node; # Typedef<uint8>->|unsigned char| last_node
    }

    # == /usr/include/sodium/crypto_hash_sha256.h ==




    # == /usr/include/sodium/randombytes.h ==


    # == /usr/include/sodium/crypto_auth_hmacsha256.h ==

    class crypto_auth_hmacsha256_state is repr('CStruct') {
        has crypto_hash_sha256_state      $.ictx; # Typedef<crypto_hash_sha256_state>->|crypto_hash_sha256_state| ictx
        has crypto_hash_sha256_state      $.octx; # Typedef<crypto_hash_sha256_state>->|crypto_hash_sha256_state| octx
    }



    # == /usr/include/sodium/crypto_secretbox.h ==

    #-From /usr/include/sodium/crypto_secretbox.h:18
    ##define crypto_secretbox_KEYBYTES crypto_secretbox_xsalsa20poly1305_KEYBYTES
    #SODIUM_EXPORT
    #size_t  crypto_secretbox_keybytes(void);
    sub crypto_secretbox_keybytes(
                                  ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_secretbox.h:22
    ##define crypto_secretbox_NONCEBYTES crypto_secretbox_xsalsa20poly1305_NONCEBYTES
    #SODIUM_EXPORT
    #size_t  crypto_secretbox_noncebytes(void);
    sub crypto_secretbox_noncebytes(
                                    ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_secretbox.h:26
    ##define crypto_secretbox_MACBYTES crypto_secretbox_xsalsa20poly1305_MACBYTES
    #SODIUM_EXPORT
    #size_t  crypto_secretbox_macbytes(void);
    sub crypto_secretbox_macbytes(
                                  ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_secretbox.h:30
    ##define crypto_secretbox_PRIMITIVE "xsalsa20poly1305"
    #SODIUM_EXPORT
    #const char *crypto_secretbox_primitive(void);
    sub crypto_secretbox_primitive(
                                   ) is native(LIB) returns Str { * }

    #-From /usr/include/sodium/crypto_secretbox.h:33
    #SODIUM_EXPORT
    #int crypto_secretbox_easy(unsigned char *c, const unsigned char *m,
    sub crypto_secretbox_easy(Pointer[uint8]                $c # unsigned char*
                             ,Pointer[uint8]                $m # const unsigned char*
                             ,ulonglong                     $mlen # long long unsigned int
                             ,Pointer[uint8]                $n # const unsigned char*
                             ,Pointer[uint8]                $k # const unsigned char*
                              ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_secretbox.h:38
    #SODIUM_EXPORT
    #int crypto_secretbox_open_easy(unsigned char *m, const unsigned char *c,
    sub crypto_secretbox_open_easy(Pointer[uint8]                $m # unsigned char*
                                  ,Pointer[uint8]                $c # const unsigned char*
                                  ,ulonglong                     $clen # long long unsigned int
                                  ,Pointer[uint8]                $n # const unsigned char*
                                  ,Pointer[uint8]                $k # const unsigned char*
                                   ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_secretbox.h:44
    #SODIUM_EXPORT
    #int crypto_secretbox_detached(unsigned char *c, unsigned char *mac,
    sub crypto_secretbox_detached(Pointer[uint8]                $c # unsigned char*
                                 ,Pointer[uint8]                $mac # unsigned char*
                                 ,Pointer[uint8]                $m # const unsigned char*
                                 ,ulonglong                     $mlen # long long unsigned int
                                 ,Pointer[uint8]                $n # const unsigned char*
                                 ,Pointer[uint8]                $k # const unsigned char*
                                  ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_secretbox.h:51
    #SODIUM_EXPORT
    #int crypto_secretbox_open_detached(unsigned char *m,
    sub crypto_secretbox_open_detached(Pointer[uint8]                $m # unsigned char*
                                      ,Pointer[uint8]                $c # const unsigned char*
                                      ,Pointer[uint8]                $mac # const unsigned char*
                                      ,ulonglong                     $clen # long long unsigned int
                                      ,Pointer[uint8]                $n # const unsigned char*
                                      ,Pointer[uint8]                $k # const unsigned char*
                                       ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_secretbox.h:63
    ##define crypto_secretbox_ZEROBYTES crypto_secretbox_xsalsa20poly1305_ZEROBYTES
    #SODIUM_EXPORT
    #size_t  crypto_secretbox_zerobytes(void);
    sub crypto_secretbox_zerobytes(
                                   ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_secretbox.h:67
    ##define crypto_secretbox_BOXZEROBYTES crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES
    #SODIUM_EXPORT
    #size_t  crypto_secretbox_boxzerobytes(void);
    sub crypto_secretbox_boxzerobytes(
                                      ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_secretbox.h:70
    #SODIUM_EXPORT
    #int crypto_secretbox(unsigned char *c, const unsigned char *m,
    sub crypto_secretbox(Pointer[uint8]                $c # unsigned char*
                        ,Pointer[uint8]                $m # const unsigned char*
                        ,ulonglong                     $mlen # long long unsigned int
                        ,Pointer[uint8]                $n # const unsigned char*
                        ,Pointer[uint8]                $k # const unsigned char*
                         ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_secretbox.h:75
    #SODIUM_EXPORT
    #int crypto_secretbox_open(unsigned char *m, const unsigned char *c,
    sub crypto_secretbox_open(Pointer[uint8]                $m # unsigned char*
                             ,Pointer[uint8]                $c # const unsigned char*
                             ,ulonglong                     $clen # long long unsigned int
                             ,Pointer[uint8]                $n # const unsigned char*
                             ,Pointer[uint8]                $k # const unsigned char*
                              ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_core_hsalsa20.h ==

    #-From /usr/include/sodium/crypto_core_hsalsa20.h:13
    ##define crypto_core_hsalsa20_OUTPUTBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_core_hsalsa20_outputbytes(void);
    sub crypto_core_hsalsa20_outputbytes(
                                         ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_core_hsalsa20.h:17
    ##define crypto_core_hsalsa20_INPUTBYTES 16U
    #SODIUM_EXPORT
    #size_t crypto_core_hsalsa20_inputbytes(void);
    sub crypto_core_hsalsa20_inputbytes(
                                        ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_core_hsalsa20.h:21
    ##define crypto_core_hsalsa20_KEYBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_core_hsalsa20_keybytes(void);
    sub crypto_core_hsalsa20_keybytes(
                                      ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_core_hsalsa20.h:25
    ##define crypto_core_hsalsa20_CONSTBYTES 16U
    #SODIUM_EXPORT
    #size_t crypto_core_hsalsa20_constbytes(void);
    sub crypto_core_hsalsa20_constbytes(
                                        ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_core_hsalsa20.h:28
    #SODIUM_EXPORT
    #int crypto_core_hsalsa20(unsigned char *out, const unsigned char *in,
    sub crypto_core_hsalsa20(Pointer[uint8]                $out # unsigned char*
                            ,Pointer[uint8]                $in # const unsigned char*
                            ,Pointer[uint8]                $k # const unsigned char*
                            ,Pointer[uint8]                $c # const unsigned char*
                             ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_auth_hmacsha512.h ==

    #-From /usr/include/sodium/crypto_auth_hmacsha512.h:17
    ##define crypto_auth_hmacsha512_BYTES 64U
    #SODIUM_EXPORT
    #size_t crypto_auth_hmacsha512_bytes(void);
    sub crypto_auth_hmacsha512_bytes(
                                     ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_auth_hmacsha512.h:21
    ##define crypto_auth_hmacsha512_KEYBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_auth_hmacsha512_keybytes(void);
    sub crypto_auth_hmacsha512_keybytes(
                                        ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_auth_hmacsha512.h:24
    #SODIUM_EXPORT
    #int crypto_auth_hmacsha512(unsigned char *out,
    sub crypto_auth_hmacsha512(Pointer[uint8]                $out # unsigned char*
                              ,Pointer[uint8]                $in # const unsigned char*
                              ,ulonglong                     $inlen # long long unsigned int
                              ,Pointer[uint8]                $k # const unsigned char*
                               ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_auth_hmacsha512.h:30
    #SODIUM_EXPORT
    #int crypto_auth_hmacsha512_verify(const unsigned char *h,
    sub crypto_auth_hmacsha512_verify(Pointer[uint8]                $h # const unsigned char*
                                     ,Pointer[uint8]                $in # const unsigned char*
                                     ,ulonglong                     $inlen # long long unsigned int
                                     ,Pointer[uint8]                $k # const unsigned char*
                                      ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_auth_hmacsha512.h:43
    #SODIUM_EXPORT
    #size_t crypto_auth_hmacsha512_statebytes(void);
    sub crypto_auth_hmacsha512_statebytes(
                                          ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_auth_hmacsha512.h:46
    #SODIUM_EXPORT
    #int crypto_auth_hmacsha512_init(crypto_auth_hmacsha512_state *state,
    sub crypto_auth_hmacsha512_init(crypto_auth_hmacsha512_state  $state # Typedef<crypto_auth_hmacsha512_state>->|crypto_auth_hmacsha512_state|*
                                   ,Pointer[uint8]                $key # const unsigned char*
                                   ,size_t                        $keylen # Typedef<size_t>->|long unsigned int|
                                    ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_auth_hmacsha512.h:51
    #SODIUM_EXPORT
    #int crypto_auth_hmacsha512_update(crypto_auth_hmacsha512_state *state,
    sub crypto_auth_hmacsha512_update(crypto_auth_hmacsha512_state  $state # Typedef<crypto_auth_hmacsha512_state>->|crypto_auth_hmacsha512_state|*
                                     ,Pointer[uint8]                $in # const unsigned char*
                                     ,ulonglong                     $inlen # long long unsigned int
                                      ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_auth_hmacsha512.h:56
    #SODIUM_EXPORT
    #int crypto_auth_hmacsha512_final(crypto_auth_hmacsha512_state *state,
    sub crypto_auth_hmacsha512_final(crypto_auth_hmacsha512_state  $state # Typedef<crypto_auth_hmacsha512_state>->|crypto_auth_hmacsha512_state|*
                                    ,Pointer[uint8]                $out # unsigned char*
                                     ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_aead_chacha20poly1305.h ==

    #-From /usr/include/sodium/crypto_aead_chacha20poly1305.h:16
    ##define crypto_aead_chacha20poly1305_KEYBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_aead_chacha20poly1305_keybytes(void);
    sub crypto_aead_chacha20poly1305_keybytes(
                                              ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_aead_chacha20poly1305.h:20
    ##define crypto_aead_chacha20poly1305_NSECBYTES 0U
    #SODIUM_EXPORT
    #size_t crypto_aead_chacha20poly1305_nsecbytes(void);
    sub crypto_aead_chacha20poly1305_nsecbytes(
                                               ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_aead_chacha20poly1305.h:24
    ##define crypto_aead_chacha20poly1305_NPUBBYTES 8U
    #SODIUM_EXPORT
    #size_t crypto_aead_chacha20poly1305_npubbytes(void);
    sub crypto_aead_chacha20poly1305_npubbytes(
                                               ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_aead_chacha20poly1305.h:28
    ##define crypto_aead_chacha20poly1305_ABYTES 16U
    #SODIUM_EXPORT
    #size_t crypto_aead_chacha20poly1305_abytes(void);
    sub crypto_aead_chacha20poly1305_abytes(
                                            ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_aead_chacha20poly1305.h:31
    #SODIUM_EXPORT
    #int crypto_aead_chacha20poly1305_encrypt(unsigned char *c,
    sub crypto_aead_chacha20poly1305_encrypt(Pointer[uint8]                $c # unsigned char*
                                            ,Pointer[ulonglong]            $clen_p # long long unsigned int*
                                            ,Pointer[uint8]                $m # const unsigned char*
                                            ,ulonglong                     $mlen # long long unsigned int
                                            ,Pointer[uint8]                $ad # const unsigned char*
                                            ,ulonglong                     $adlen # long long unsigned int
                                            ,Pointer[uint8]                $nsec # const unsigned char*
                                            ,Pointer[uint8]                $npub # const unsigned char*
                                            ,Pointer[uint8]                $k # const unsigned char*
                                             ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_aead_chacha20poly1305.h:42
    #SODIUM_EXPORT
    #int crypto_aead_chacha20poly1305_decrypt(unsigned char *m,
    sub crypto_aead_chacha20poly1305_decrypt(Pointer[uint8]                $m # unsigned char*
                                            ,Pointer[ulonglong]            $mlen_p # long long unsigned int*
                                            ,Pointer[uint8]                $nsec # unsigned char*
                                            ,Pointer[uint8]                $c # const unsigned char*
                                            ,ulonglong                     $clen # long long unsigned int
                                            ,Pointer[uint8]                $ad # const unsigned char*
                                            ,ulonglong                     $adlen # long long unsigned int
                                            ,Pointer[uint8]                $npub # const unsigned char*
                                            ,Pointer[uint8]                $k # const unsigned char*
                                             ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_aead_chacha20poly1305.h:55
    ##define crypto_aead_chacha20poly1305_IETF_NPUBBYTES 12U
    #SODIUM_EXPORT
    #size_t crypto_aead_chacha20poly1305_ietf_npubbytes(void);
    sub crypto_aead_chacha20poly1305_ietf_npubbytes(
                                                    ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_aead_chacha20poly1305.h:58
    #SODIUM_EXPORT
    #int crypto_aead_chacha20poly1305_ietf_encrypt(unsigned char *c,
    sub crypto_aead_chacha20poly1305_ietf_encrypt(Pointer[uint8]                $c # unsigned char*
                                                 ,Pointer[ulonglong]            $clen_p # long long unsigned int*
                                                 ,Pointer[uint8]                $m # const unsigned char*
                                                 ,ulonglong                     $mlen # long long unsigned int
                                                 ,Pointer[uint8]                $ad # const unsigned char*
                                                 ,ulonglong                     $adlen # long long unsigned int
                                                 ,Pointer[uint8]                $nsec # const unsigned char*
                                                 ,Pointer[uint8]                $npub # const unsigned char*
                                                 ,Pointer[uint8]                $k # const unsigned char*
                                                  ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_aead_chacha20poly1305.h:69
    #SODIUM_EXPORT
    #int crypto_aead_chacha20poly1305_ietf_decrypt(unsigned char *m,
    sub crypto_aead_chacha20poly1305_ietf_decrypt(Pointer[uint8]                $m # unsigned char*
                                                 ,Pointer[ulonglong]            $mlen_p # long long unsigned int*
                                                 ,Pointer[uint8]                $nsec # unsigned char*
                                                 ,Pointer[uint8]                $c # const unsigned char*
                                                 ,ulonglong                     $clen # long long unsigned int
                                                 ,Pointer[uint8]                $ad # const unsigned char*
                                                 ,ulonglong                     $adlen # long long unsigned int
                                                 ,Pointer[uint8]                $npub # const unsigned char*
                                                 ,Pointer[uint8]                $k # const unsigned char*
                                                  ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_onetimeauth_poly1305.h ==

    #-From /usr/include/sodium/crypto_onetimeauth_poly1305.h:25
    ##define crypto_onetimeauth_poly1305_BYTES 16U
    #SODIUM_EXPORT
    #size_t crypto_onetimeauth_poly1305_bytes(void);
    sub crypto_onetimeauth_poly1305_bytes(
                                          ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_onetimeauth_poly1305.h:29
    ##define crypto_onetimeauth_poly1305_KEYBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_onetimeauth_poly1305_keybytes(void);
    sub crypto_onetimeauth_poly1305_keybytes(
                                             ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_onetimeauth_poly1305.h:32
    #SODIUM_EXPORT
    #int crypto_onetimeauth_poly1305(unsigned char *out,
    sub crypto_onetimeauth_poly1305(Pointer[uint8]                $out # unsigned char*
                                   ,Pointer[uint8]                $in # const unsigned char*
                                   ,ulonglong                     $inlen # long long unsigned int
                                   ,Pointer[uint8]                $k # const unsigned char*
                                    ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_onetimeauth_poly1305.h:38
    #SODIUM_EXPORT
    #int crypto_onetimeauth_poly1305_verify(const unsigned char *h,
    sub crypto_onetimeauth_poly1305_verify(Pointer[uint8]                $h # const unsigned char*
                                          ,Pointer[uint8]                $in # const unsigned char*
                                          ,ulonglong                     $inlen # long long unsigned int
                                          ,Pointer[uint8]                $k # const unsigned char*
                                           ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_onetimeauth_poly1305.h:45
    #SODIUM_EXPORT
    #int crypto_onetimeauth_poly1305_init(crypto_onetimeauth_poly1305_state *state,
    sub crypto_onetimeauth_poly1305_init(crypto_onetimeauth_poly1305_state$state # Typedef<crypto_onetimeauth_poly1305_state>->|crypto_onetimeauth_poly1305_state|*
                                        ,Pointer[uint8]                $key # const unsigned char*
                                         ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_onetimeauth_poly1305.h:49
    #SODIUM_EXPORT
    #int crypto_onetimeauth_poly1305_update(crypto_onetimeauth_poly1305_state *state,
    sub crypto_onetimeauth_poly1305_update(crypto_onetimeauth_poly1305_state$state # Typedef<crypto_onetimeauth_poly1305_state>->|crypto_onetimeauth_poly1305_state|*
                                          ,Pointer[uint8]                $in # const unsigned char*
                                          ,ulonglong                     $inlen # long long unsigned int
                                           ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_onetimeauth_poly1305.h:54
    #SODIUM_EXPORT
    #int crypto_onetimeauth_poly1305_final(crypto_onetimeauth_poly1305_state *state,
    sub crypto_onetimeauth_poly1305_final(crypto_onetimeauth_poly1305_state$state # Typedef<crypto_onetimeauth_poly1305_state>->|crypto_onetimeauth_poly1305_state|*
                                         ,Pointer[uint8]                $out # unsigned char*
                                          ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_onetimeauth_poly1305.h:59
    #int _crypto_onetimeauth_poly1305_pick_best_implementation(void);
    sub _crypto_onetimeauth_poly1305_pick_best_implementation(
                                                              ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_stream_salsa208.h ==

    #-From /usr/include/sodium/crypto_stream_salsa208.h:24
    ##define crypto_stream_salsa208_KEYBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_stream_salsa208_keybytes(void);
    sub crypto_stream_salsa208_keybytes(
                                        ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_stream_salsa208.h:28
    ##define crypto_stream_salsa208_NONCEBYTES 8U
    #SODIUM_EXPORT
    #size_t crypto_stream_salsa208_noncebytes(void);
    sub crypto_stream_salsa208_noncebytes(
                                          ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_stream_salsa208.h:31
    #SODIUM_EXPORT
    #int crypto_stream_salsa208(unsigned char *c, unsigned long long clen,
    sub crypto_stream_salsa208(Pointer[uint8]                $c # unsigned char*
                              ,ulonglong                     $clen # long long unsigned int
                              ,Pointer[uint8]                $n # const unsigned char*
                              ,Pointer[uint8]                $k # const unsigned char*
                               ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_stream_salsa208.h:35
    #SODIUM_EXPORT
    #int crypto_stream_salsa208_xor(unsigned char *c, const unsigned char *m,
    sub crypto_stream_salsa208_xor(Pointer[uint8]                $c # unsigned char*
                                  ,Pointer[uint8]                $m # const unsigned char*
                                  ,ulonglong                     $mlen # long long unsigned int
                                  ,Pointer[uint8]                $n # const unsigned char*
                                  ,Pointer[uint8]                $k # const unsigned char*
                                   ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_stream_aes128ctr.h ==

    #-From /usr/include/sodium/crypto_stream_aes128ctr.h:24
    ##define crypto_stream_aes128ctr_KEYBYTES 16U
    #SODIUM_EXPORT
    #size_t crypto_stream_aes128ctr_keybytes(void);
    sub crypto_stream_aes128ctr_keybytes(
                                         ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_stream_aes128ctr.h:28
    ##define crypto_stream_aes128ctr_NONCEBYTES 16U
    #SODIUM_EXPORT
    #size_t crypto_stream_aes128ctr_noncebytes(void);
    sub crypto_stream_aes128ctr_noncebytes(
                                           ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_stream_aes128ctr.h:32
    ##define crypto_stream_aes128ctr_BEFORENMBYTES 1408U
    #SODIUM_EXPORT
    #size_t crypto_stream_aes128ctr_beforenmbytes(void);
    sub crypto_stream_aes128ctr_beforenmbytes(
                                              ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_stream_aes128ctr.h:35
    #SODIUM_EXPORT
    #int crypto_stream_aes128ctr(unsigned char *out, unsigned long long outlen,
    sub crypto_stream_aes128ctr(Pointer[uint8]                $out # unsigned char*
                               ,ulonglong                     $outlen # long long unsigned int
                               ,Pointer[uint8]                $n # const unsigned char*
                               ,Pointer[uint8]                $k # const unsigned char*
                                ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_stream_aes128ctr.h:39
    #SODIUM_EXPORT
    #int crypto_stream_aes128ctr_xor(unsigned char *out, const unsigned char *in,
    sub crypto_stream_aes128ctr_xor(Pointer[uint8]                $out # unsigned char*
                                   ,Pointer[uint8]                $in # const unsigned char*
                                   ,ulonglong                     $inlen # long long unsigned int
                                   ,Pointer[uint8]                $n # const unsigned char*
                                   ,Pointer[uint8]                $k # const unsigned char*
                                    ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_stream_aes128ctr.h:44
    #SODIUM_EXPORT
    #int crypto_stream_aes128ctr_beforenm(unsigned char *c, const unsigned char *k);
    sub crypto_stream_aes128ctr_beforenm(Pointer[uint8]                $c # unsigned char*
                                        ,Pointer[uint8]                $k # const unsigned char*
                                         ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_stream_aes128ctr.h:47
    #SODIUM_EXPORT
    #int crypto_stream_aes128ctr_afternm(unsigned char *out, unsigned long long len,
    sub crypto_stream_aes128ctr_afternm(Pointer[uint8]                $out # unsigned char*
                                       ,ulonglong                     $len # long long unsigned int
                                       ,Pointer[uint8]                $nonce # const unsigned char*
                                       ,Pointer[uint8]                $c # const unsigned char*
                                        ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_stream_aes128ctr.h:51
    #SODIUM_EXPORT
    #int crypto_stream_aes128ctr_xor_afternm(unsigned char *out, const unsigned char *in,
    sub crypto_stream_aes128ctr_xor_afternm(Pointer[uint8]                $out # unsigned char*
                                           ,Pointer[uint8]                $in # const unsigned char*
                                           ,ulonglong                     $len # long long unsigned int
                                           ,Pointer[uint8]                $nonce # const unsigned char*
                                           ,Pointer[uint8]                $c # const unsigned char*
                                            ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_stream_xsalsa20.h ==

    #-From /usr/include/sodium/crypto_stream_xsalsa20.h:25
    ##define crypto_stream_xsalsa20_KEYBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_stream_xsalsa20_keybytes(void);
    sub crypto_stream_xsalsa20_keybytes(
                                        ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_stream_xsalsa20.h:29
    ##define crypto_stream_xsalsa20_NONCEBYTES 24U
    #SODIUM_EXPORT
    #size_t crypto_stream_xsalsa20_noncebytes(void);
    sub crypto_stream_xsalsa20_noncebytes(
                                          ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_stream_xsalsa20.h:32
    #SODIUM_EXPORT
    #int crypto_stream_xsalsa20(unsigned char *c, unsigned long long clen,
    sub crypto_stream_xsalsa20(Pointer[uint8]                $c # unsigned char*
                              ,ulonglong                     $clen # long long unsigned int
                              ,Pointer[uint8]                $n # const unsigned char*
                              ,Pointer[uint8]                $k # const unsigned char*
                               ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_stream_xsalsa20.h:36
    #SODIUM_EXPORT
    #int crypto_stream_xsalsa20_xor(unsigned char *c, const unsigned char *m,
    sub crypto_stream_xsalsa20_xor(Pointer[uint8]                $c # unsigned char*
                                  ,Pointer[uint8]                $m # const unsigned char*
                                  ,ulonglong                     $mlen # long long unsigned int
                                  ,Pointer[uint8]                $n # const unsigned char*
                                  ,Pointer[uint8]                $k # const unsigned char*
                                   ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_stream_xsalsa20.h:41
    #SODIUM_EXPORT
    #int crypto_stream_xsalsa20_xor_ic(unsigned char *c, const unsigned char *m,
    sub crypto_stream_xsalsa20_xor_ic(Pointer[uint8]                $c # unsigned char*
                                     ,Pointer[uint8]                $m # const unsigned char*
                                     ,ulonglong                     $mlen # long long unsigned int
                                     ,Pointer[uint8]                $n # const unsigned char*
                                     ,uint64                      $ic # Typedef<uint64>->|long unsigned int|
                                     ,Pointer[uint8]                $k # const unsigned char*
                                      ) is native(LIB) returns int32 { * }




    # == /usr/include/sodium/crypto_verify_32.h ==

    #-From /usr/include/sodium/crypto_verify_32.h:13
    ##define crypto_verify_32_BYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_verify_32_bytes(void);
    sub crypto_verify_32_bytes(
                               ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_verify_32.h:16
    #SODIUM_EXPORT
    #int crypto_verify_32(const unsigned char *x, const unsigned char *y)
    sub crypto_verify_32(Pointer[uint8]                $x # const unsigned char*
                        ,Pointer[uint8]                $y # const unsigned char*
                         ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_stream_salsa2012.h ==

    #-From /usr/include/sodium/crypto_stream_salsa2012.h:24
    ##define crypto_stream_salsa2012_KEYBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_stream_salsa2012_keybytes(void);
    sub crypto_stream_salsa2012_keybytes(
                                         ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_stream_salsa2012.h:28
    ##define crypto_stream_salsa2012_NONCEBYTES 8U
    #SODIUM_EXPORT
    #size_t crypto_stream_salsa2012_noncebytes(void);
    sub crypto_stream_salsa2012_noncebytes(
                                           ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_stream_salsa2012.h:31
    #SODIUM_EXPORT
    #int crypto_stream_salsa2012(unsigned char *c, unsigned long long clen,
    sub crypto_stream_salsa2012(Pointer[uint8]                $c # unsigned char*
                               ,ulonglong                     $clen # long long unsigned int
                               ,Pointer[uint8]                $n # const unsigned char*
                               ,Pointer[uint8]                $k # const unsigned char*
                                ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_stream_salsa2012.h:35
    #SODIUM_EXPORT
    #int crypto_stream_salsa2012_xor(unsigned char *c, const unsigned char *m,
    sub crypto_stream_salsa2012_xor(Pointer[uint8]                $c # unsigned char*
                                   ,Pointer[uint8]                $m # const unsigned char*
                                   ,ulonglong                     $mlen # long long unsigned int
                                   ,Pointer[uint8]                $n # const unsigned char*
                                   ,Pointer[uint8]                $k # const unsigned char*
                                    ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/utils.h ==

    #-From /usr/include/sodium/utils.h:22
    #SODIUM_EXPORT
    #void sodium_memzero(void * const pnt, const size_t len);
    sub sodium_memzero(Pointer                       $pnt # const void*
                      ,size_t                        $len # const Typedef<size_t>->|long unsigned int|
                       ) is native(LIB)  { * }

    #-From /usr/include/sodium/utils.h:31
    #/*
    # * WARNING: sodium_memcmp() must be used to verify if two secret keys
    # * are equal, in constant time.
    # * It returns 0 if the keys are equal, and -1 if they differ.
    # * This function is not designed for lexicographical comparisons.
    # */
    #SODIUM_EXPORT
    #int sodium_memcmp(const void * const b1_, const void * const b2_, size_t len)
    sub sodium_memcmp(Pointer                       $b1_ # const const void*
                     ,Pointer                       $b2_ # const const void*
                     ,size_t                        $len # Typedef<size_t>->|long unsigned int|
                      ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/utils.h:41
    #/*
    # * sodium_compare() returns -1 if b1_ < b2_, 1 if b1_ > b2_ and 0 if b1_ == b2_
    # * It is suitable for lexicographical comparisons, or to compare nonces
    # * and counters stored in little-endian format.
    # * However, it is slower than sodium_memcmp().
    # */
    #SODIUM_EXPORT
    #int sodium_compare(const unsigned char *b1_, const unsigned char *b2_,
    sub sodium_compare(Pointer[uint8]                $b1_ # const unsigned char*
                      ,Pointer[uint8]                $b2_ # const unsigned char*
                      ,size_t                        $len # Typedef<size_t>->|long unsigned int|
                       ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/utils.h:46
    #SODIUM_EXPORT
    #int sodium_is_zero(const unsigned char *n, const size_t nlen);
    sub sodium_is_zero(Pointer[uint8]                $n # const unsigned char*
                      ,size_t                        $nlen # const Typedef<size_t>->|long unsigned int|
                       ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/utils.h:49
    #SODIUM_EXPORT
    #void sodium_increment(unsigned char *n, const size_t nlen);
    sub sodium_increment(Pointer[uint8]                $n # unsigned char*
                        ,size_t                        $nlen # const Typedef<size_t>->|long unsigned int|
                         ) is native(LIB)  { * }

    #-From /usr/include/sodium/utils.h:52
    #SODIUM_EXPORT
    #void sodium_add(unsigned char *a, const unsigned char *b, const size_t len);
    sub sodium_add(Pointer[uint8]                $a # unsigned char*
                  ,Pointer[uint8]                $b # const unsigned char*
                  ,size_t                        $len # const Typedef<size_t>->|long unsigned int|
                   ) is native(LIB)  { * }

    #-From /usr/include/sodium/utils.h:55
    #SODIUM_EXPORT
    #char *sodium_bin2hex(char * const hex, const size_t hex_maxlen,
    sub sodium_bin2hex(Str $hex, size_t $hex_maxlen, CArray[uint8] $bin, size_t $bin_len --> Str ) is native(LIB) { * }

    #-From /usr/include/sodium/utils.h:59
    #SODIUM_EXPORT
    #int sodium_hex2bin(unsigned char * const bin, const size_t bin_maxlen,
    sub sodium_hex2bin(Pointer[uint8]                $bin # const unsigned char*
                      ,size_t                        $bin_maxlen # const Typedef<size_t>->|long unsigned int|
                      ,Str                           $hex # const const char*
                      ,size_t                        $hex_len # const Typedef<size_t>->|long unsigned int|
                      ,Str                           $ignore # const const char*
                      ,Pointer[size_t]               $bin_len # const Typedef<size_t>->|long unsigned int|*
                      ,Pointer[Str]                  $hex_end # const const char**
                       ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/utils.h:65
    #SODIUM_EXPORT
    #int sodium_mlock(void * const addr, const size_t len);
    sub sodium_mlock(Pointer                       $addr # const void*
                    ,size_t                        $len # const Typedef<size_t>->|long unsigned int|
                     ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/utils.h:68
    #SODIUM_EXPORT
    #int sodium_munlock(void * const addr, const size_t len);
    sub sodium_munlock(Pointer                       $addr # const void*
                      ,size_t                        $len # const Typedef<size_t>->|long unsigned int|
                       ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/utils.h:105
    #SODIUM_EXPORT
    #void *sodium_malloc(const size_t size)
    sub sodium_malloc(size_t $size # const Typedef<size_t>->|long unsigned int|
                      ) is native(LIB) returns Pointer { * }

    #-From /usr/include/sodium/utils.h:109
    #SODIUM_EXPORT
    #void *sodium_allocarray(size_t count, size_t size)
    sub sodium_allocarray(size_t                        $count # Typedef<size_t>->|long unsigned int|
                         ,size_t                        $size # Typedef<size_t>->|long unsigned int|
                          ) is native(LIB) returns Pointer { * }

    #-From /usr/include/sodium/utils.h:113
    #SODIUM_EXPORT
    #void sodium_free(void *ptr);
    sub sodium_free(Pointer $ptr # void*
                    ) is native(LIB)  { * }

    #-From /usr/include/sodium/utils.h:116
    #SODIUM_EXPORT
    #int sodium_mprotect_noaccess(void *ptr);
    sub sodium_mprotect_noaccess(Pointer $ptr # void*
                                 ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/utils.h:119
    #SODIUM_EXPORT
    #int sodium_mprotect_readonly(void *ptr);
    sub sodium_mprotect_readonly(Pointer $ptr # void*
                                 ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/utils.h:122
    #SODIUM_EXPORT
    #int sodium_mprotect_readwrite(void *ptr);
    sub sodium_mprotect_readwrite(Pointer $ptr # void*
                                  ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/utils.h:126
    #int _sodium_alloc_init(void);
    sub _sodium_alloc_init(
                           ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_aead_aes256gcm.h ==

    #-From /usr/include/sodium/crypto_aead_aes256gcm.h:15
    #SODIUM_EXPORT
    #int crypto_aead_aes256gcm_is_available(void);
    sub crypto_aead_aes256gcm_is_available(
                                           ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_aead_aes256gcm.h:19
    ##define crypto_aead_aes256gcm_KEYBYTES  32U
    #SODIUM_EXPORT
    #size_t crypto_aead_aes256gcm_keybytes(void);
    sub crypto_aead_aes256gcm_keybytes(
                                       ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_aead_aes256gcm.h:23
    ##define crypto_aead_aes256gcm_NSECBYTES 0U
    #SODIUM_EXPORT
    #size_t crypto_aead_aes256gcm_nsecbytes(void);
    sub crypto_aead_aes256gcm_nsecbytes(
                                        ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_aead_aes256gcm.h:27
    ##define crypto_aead_aes256gcm_NPUBBYTES 12U
    #SODIUM_EXPORT
    #size_t crypto_aead_aes256gcm_npubbytes(void);
    sub crypto_aead_aes256gcm_npubbytes(
                                        ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_aead_aes256gcm.h:31
    ##define crypto_aead_aes256gcm_ABYTES    16U
    #SODIUM_EXPORT
    #size_t crypto_aead_aes256gcm_abytes(void);
    sub crypto_aead_aes256gcm_abytes(
                                     ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_aead_aes256gcm.h:35
    #SODIUM_EXPORT
    #size_t crypto_aead_aes256gcm_statebytes(void);
    sub crypto_aead_aes256gcm_statebytes(
                                         ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_aead_aes256gcm.h:38
    #SODIUM_EXPORT
    #int crypto_aead_aes256gcm_encrypt(unsigned char *c,
    sub crypto_aead_aes256gcm_encrypt(Pointer[uint8]                $c # unsigned char*
                                     ,Pointer[ulonglong]            $clen_p # long long unsigned int*
                                     ,Pointer[uint8]                $m # const unsigned char*
                                     ,ulonglong                     $mlen # long long unsigned int
                                     ,Pointer[uint8]                $ad # const unsigned char*
                                     ,ulonglong                     $adlen # long long unsigned int
                                     ,Pointer[uint8]                $nsec # const unsigned char*
                                     ,Pointer[uint8]                $npub # const unsigned char*
                                     ,Pointer[uint8]                $k # const unsigned char*
                                      ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_aead_aes256gcm.h:49
    #SODIUM_EXPORT
    #int crypto_aead_aes256gcm_decrypt(unsigned char *m,
    sub crypto_aead_aes256gcm_decrypt(Pointer[uint8]                $m # unsigned char*
                                     ,Pointer[ulonglong]            $mlen_p # long long unsigned int*
                                     ,Pointer[uint8]                $nsec # unsigned char*
                                     ,Pointer[uint8]                $c # const unsigned char*
                                     ,ulonglong                     $clen # long long unsigned int
                                     ,Pointer[uint8]                $ad # const unsigned char*
                                     ,ulonglong                     $adlen # long long unsigned int
                                     ,Pointer[uint8]                $npub # const unsigned char*
                                     ,Pointer[uint8]                $k # const unsigned char*
                                      ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_aead_aes256gcm.h:61
    #SODIUM_EXPORT
    #int crypto_aead_aes256gcm_beforenm(crypto_aead_aes256gcm_state *ctx_,
    sub crypto_aead_aes256gcm_beforenm(Pointer[CArray[uint8]]        $ctx_ # Typedef<crypto_aead_aes256gcm_state>->|unsigned char[512]|*
                                      ,Pointer[uint8]                $k # const unsigned char*
                                       ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_aead_aes256gcm.h:65
    #SODIUM_EXPORT
    #int crypto_aead_aes256gcm_encrypt_afternm(unsigned char *c,
    sub crypto_aead_aes256gcm_encrypt_afternm(Pointer[uint8]                $c # unsigned char*
                                             ,Pointer[ulonglong]            $clen_p # long long unsigned int*
                                             ,Pointer[uint8]                $m # const unsigned char*
                                             ,ulonglong                     $mlen # long long unsigned int
                                             ,Pointer[uint8]                $ad # const unsigned char*
                                             ,ulonglong                     $adlen # long long unsigned int
                                             ,Pointer[uint8]                $nsec # const unsigned char*
                                             ,Pointer[uint8]                $npub # const unsigned char*
                                             ,Pointer[CArray[uint8]]        $ctx_ # const Typedef<crypto_aead_aes256gcm_state>->|unsigned char[512]|*
                                              ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_aead_aes256gcm.h:76
    #SODIUM_EXPORT
    #int crypto_aead_aes256gcm_decrypt_afternm(unsigned char *m,
    sub crypto_aead_aes256gcm_decrypt_afternm(Pointer[uint8]                $m # unsigned char*
                                             ,Pointer[ulonglong]            $mlen_p # long long unsigned int*
                                             ,Pointer[uint8]                $nsec # unsigned char*
                                             ,Pointer[uint8]                $c # const unsigned char*
                                             ,ulonglong                     $clen # long long unsigned int
                                             ,Pointer[uint8]                $ad # const unsigned char*
                                             ,ulonglong                     $adlen # long long unsigned int
                                             ,Pointer[uint8]                $npub # const unsigned char*
                                             ,Pointer[CArray[uint8]]        $ctx_ # const Typedef<crypto_aead_aes256gcm_state>->|unsigned char[512]|*
                                              ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_sign.h ==

    #-From /usr/include/sodium/crypto_sign.h:25
    ##define crypto_sign_BYTES crypto_sign_ed25519_BYTES
    #SODIUM_EXPORT
    #size_t  crypto_sign_bytes(void);
    sub crypto_sign_bytes(
                          ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_sign.h:29
    ##define crypto_sign_SEEDBYTES crypto_sign_ed25519_SEEDBYTES
    #SODIUM_EXPORT
    #size_t  crypto_sign_seedbytes(void);
    sub crypto_sign_seedbytes(
                              ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_sign.h:33
    ##define crypto_sign_PUBLICKEYBYTES crypto_sign_ed25519_PUBLICKEYBYTES
    #SODIUM_EXPORT
    #size_t  crypto_sign_publickeybytes(void);
    sub crypto_sign_publickeybytes(
                                   ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_sign.h:37
    ##define crypto_sign_SECRETKEYBYTES crypto_sign_ed25519_SECRETKEYBYTES
    #SODIUM_EXPORT
    #size_t  crypto_sign_secretkeybytes(void);
    sub crypto_sign_secretkeybytes(
                                   ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_sign.h:41
    ##define crypto_sign_PRIMITIVE "ed25519"
    #SODIUM_EXPORT
    #const char *crypto_sign_primitive(void);
    sub crypto_sign_primitive(
                              ) is native(LIB) returns Str { * }

    #-From /usr/include/sodium/crypto_sign.h:44
    #SODIUM_EXPORT
    #int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
    sub crypto_sign_seed_keypair(Pointer[uint8]                $pk # unsigned char*
                                ,Pointer[uint8]                $sk # unsigned char*
                                ,Pointer[uint8]                $seed # const unsigned char*
                                 ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_sign.h:48
    #SODIUM_EXPORT
    #int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
    sub crypto_sign_keypair(Pointer[uint8]                $pk # unsigned char*
                           ,Pointer[uint8]                $sk # unsigned char*
                            ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_sign.h:51
    #SODIUM_EXPORT
    #int crypto_sign(unsigned char *sm, unsigned long long *smlen_p,
    sub crypto_sign(Pointer[uint8]                $sm # unsigned char*
                   ,Pointer[ulonglong]            $smlen_p # long long unsigned int*
                   ,Pointer[uint8]                $m # const unsigned char*
                   ,ulonglong                     $mlen # long long unsigned int
                   ,Pointer[uint8]                $sk # const unsigned char*
                    ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_sign.h:56
    #SODIUM_EXPORT
    #int crypto_sign_open(unsigned char *m, unsigned long long *mlen_p,
    sub crypto_sign_open(Pointer[uint8]                $m # unsigned char*
                        ,Pointer[ulonglong]            $mlen_p # long long unsigned int*
                        ,Pointer[uint8]                $sm # const unsigned char*
                        ,ulonglong                     $smlen # long long unsigned int
                        ,Pointer[uint8]                $pk # const unsigned char*
                         ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_sign.h:62
    #SODIUM_EXPORT
    #int crypto_sign_detached(unsigned char *sig, unsigned long long *siglen_p,
    sub crypto_sign_detached(Pointer[uint8]                $sig # unsigned char*
                            ,Pointer[ulonglong]            $siglen_p # long long unsigned int*
                            ,Pointer[uint8]                $m # const unsigned char*
                            ,ulonglong                     $mlen # long long unsigned int
                            ,Pointer[uint8]                $sk # const unsigned char*
                             ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_sign.h:67
    #SODIUM_EXPORT
    #int crypto_sign_verify_detached(const unsigned char *sig,
    sub crypto_sign_verify_detached(Pointer[uint8]                $sig # const unsigned char*
                                   ,Pointer[uint8]                $m # const unsigned char*
                                   ,ulonglong                     $mlen # long long unsigned int
                                   ,Pointer[uint8]                $pk # const unsigned char*
                                    ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_generichash_blake2b.h ==

    #-From /usr/include/sodium/crypto_generichash_blake2b.h:40
    ##define crypto_generichash_blake2b_BYTES_MIN     16U
    #SODIUM_EXPORT
    #size_t crypto_generichash_blake2b_bytes_min(void);
    sub crypto_generichash_blake2b_bytes_min(
                                             ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_generichash_blake2b.h:44
    ##define crypto_generichash_blake2b_BYTES_MAX     64U
    #SODIUM_EXPORT
    #size_t crypto_generichash_blake2b_bytes_max(void);
    sub crypto_generichash_blake2b_bytes_max(
                                             ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_generichash_blake2b.h:48
    ##define crypto_generichash_blake2b_BYTES         32U
    #SODIUM_EXPORT
    #size_t crypto_generichash_blake2b_bytes(void);
    sub crypto_generichash_blake2b_bytes(
                                         ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_generichash_blake2b.h:52
    ##define crypto_generichash_blake2b_KEYBYTES_MIN  16U
    #SODIUM_EXPORT
    #size_t crypto_generichash_blake2b_keybytes_min(void);
    sub crypto_generichash_blake2b_keybytes_min(
                                                ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_generichash_blake2b.h:56
    ##define crypto_generichash_blake2b_KEYBYTES_MAX  64U
    #SODIUM_EXPORT
    #size_t crypto_generichash_blake2b_keybytes_max(void);
    sub crypto_generichash_blake2b_keybytes_max(
                                                ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_generichash_blake2b.h:60
    ##define crypto_generichash_blake2b_KEYBYTES      32U
    #SODIUM_EXPORT
    #size_t crypto_generichash_blake2b_keybytes(void);
    sub crypto_generichash_blake2b_keybytes(
                                            ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_generichash_blake2b.h:64
    ##define crypto_generichash_blake2b_SALTBYTES     16U
    #SODIUM_EXPORT
    #size_t crypto_generichash_blake2b_saltbytes(void);
    sub crypto_generichash_blake2b_saltbytes(
                                             ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_generichash_blake2b.h:68
    ##define crypto_generichash_blake2b_PERSONALBYTES 16U
    #SODIUM_EXPORT
    #size_t crypto_generichash_blake2b_personalbytes(void);
    sub crypto_generichash_blake2b_personalbytes(
                                                 ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_generichash_blake2b.h:71
    #SODIUM_EXPORT
    #int crypto_generichash_blake2b(unsigned char *out, size_t outlen,
    sub crypto_generichash_blake2b(Pointer[uint8]                $out # unsigned char*
                                  ,size_t                        $outlen # Typedef<size_t>->|long unsigned int|
                                  ,Pointer[uint8]                $in # const unsigned char*
                                  ,ulonglong                     $inlen # long long unsigned int
                                  ,Pointer[uint8]                $key # const unsigned char*
                                  ,size_t                        $keylen # Typedef<size_t>->|long unsigned int|
                                   ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_generichash_blake2b.h:77
    #SODIUM_EXPORT
    #int crypto_generichash_blake2b_salt_personal(unsigned char *out, size_t outlen,
    sub crypto_generichash_blake2b_salt_personal(Pointer[uint8]                $out # unsigned char*
                                                ,size_t                        $outlen # Typedef<size_t>->|long unsigned int|
                                                ,Pointer[uint8]                $in # const unsigned char*
                                                ,ulonglong                     $inlen # long long unsigned int
                                                ,Pointer[uint8]                $key # const unsigned char*
                                                ,size_t                        $keylen # Typedef<size_t>->|long unsigned int|
                                                ,Pointer[uint8]                $salt # const unsigned char*
                                                ,Pointer[uint8]                $personal # const unsigned char*
                                                 ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_generichash_blake2b.h:86
    #SODIUM_EXPORT
    #int crypto_generichash_blake2b_init(crypto_generichash_blake2b_state *state,
    sub crypto_generichash_blake2b_init(crypto_generichash_blake2b_state$state # Typedef<crypto_generichash_blake2b_state>->|crypto_generichash_blake2b_state|*
                                       ,Pointer[uint8]                $key # const unsigned char*
                                       ,size_t                        $keylen # const Typedef<size_t>->|long unsigned int|
                                       ,size_t                        $outlen # const Typedef<size_t>->|long unsigned int|
                                        ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_generichash_blake2b.h:91
    #SODIUM_EXPORT
    #int crypto_generichash_blake2b_init_salt_personal(crypto_generichash_blake2b_state *state,
    sub crypto_generichash_blake2b_init_salt_personal(crypto_generichash_blake2b_state$state # Typedef<crypto_generichash_blake2b_state>->|crypto_generichash_blake2b_state|*
                                                     ,Pointer[uint8]                $key # const unsigned char*
                                                     ,size_t                        $keylen # const Typedef<size_t>->|long unsigned int|
                                                     ,size_t                        $outlen # const Typedef<size_t>->|long unsigned int|
                                                     ,Pointer[uint8]                $salt # const unsigned char*
                                                     ,Pointer[uint8]                $personal # const unsigned char*
                                                      ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_generichash_blake2b.h:98
    #SODIUM_EXPORT
    #int crypto_generichash_blake2b_update(crypto_generichash_blake2b_state *state,
    sub crypto_generichash_blake2b_update(crypto_generichash_blake2b_state$state # Typedef<crypto_generichash_blake2b_state>->|crypto_generichash_blake2b_state|*
                                         ,Pointer[uint8]                $in # const unsigned char*
                                         ,ulonglong                     $inlen # long long unsigned int
                                          ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_generichash_blake2b.h:103
    #SODIUM_EXPORT
    #int crypto_generichash_blake2b_final(crypto_generichash_blake2b_state *state,
    sub crypto_generichash_blake2b_final(crypto_generichash_blake2b_state$state # Typedef<crypto_generichash_blake2b_state>->|crypto_generichash_blake2b_state|*
                                        ,Pointer[uint8]                $out # unsigned char*
                                        ,size_t                        $outlen # const Typedef<size_t>->|long unsigned int|
                                         ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_generichash_blake2b.h:109
    #int _crypto_generichash_blake2b_pick_best_implementation(void);
    sub _crypto_generichash_blake2b_pick_best_implementation(
                                                             ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_core_salsa2012.h ==

    #-From /usr/include/sodium/crypto_core_salsa2012.h:13
    ##define crypto_core_salsa2012_OUTPUTBYTES 64U
    #SODIUM_EXPORT
    #size_t crypto_core_salsa2012_outputbytes(void);
    sub crypto_core_salsa2012_outputbytes(
                                          ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_core_salsa2012.h:17
    ##define crypto_core_salsa2012_INPUTBYTES 16U
    #SODIUM_EXPORT
    #size_t crypto_core_salsa2012_inputbytes(void);
    sub crypto_core_salsa2012_inputbytes(
                                         ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_core_salsa2012.h:21
    ##define crypto_core_salsa2012_KEYBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_core_salsa2012_keybytes(void);
    sub crypto_core_salsa2012_keybytes(
                                       ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_core_salsa2012.h:25
    ##define crypto_core_salsa2012_CONSTBYTES 16U
    #SODIUM_EXPORT
    #size_t crypto_core_salsa2012_constbytes(void);
    sub crypto_core_salsa2012_constbytes(
                                         ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_core_salsa2012.h:28
    #SODIUM_EXPORT
    #int crypto_core_salsa2012(unsigned char *out, const unsigned char *in,
    sub crypto_core_salsa2012(Pointer[uint8]                $out # unsigned char*
                             ,Pointer[uint8]                $in # const unsigned char*
                             ,Pointer[uint8]                $k # const unsigned char*
                             ,Pointer[uint8]                $c # const unsigned char*
                              ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_stream_salsa20.h ==

    #-From /usr/include/sodium/crypto_stream_salsa20.h:25
    ##define crypto_stream_salsa20_KEYBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_stream_salsa20_keybytes(void);
    sub crypto_stream_salsa20_keybytes(
                                       ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_stream_salsa20.h:29
    ##define crypto_stream_salsa20_NONCEBYTES 8U
    #SODIUM_EXPORT
    #size_t crypto_stream_salsa20_noncebytes(void);
    sub crypto_stream_salsa20_noncebytes(
                                         ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_stream_salsa20.h:32
    #SODIUM_EXPORT
    #int crypto_stream_salsa20(unsigned char *c, unsigned long long clen,
    sub crypto_stream_salsa20(Pointer[uint8]                $c # unsigned char*
                             ,ulonglong                     $clen # long long unsigned int
                             ,Pointer[uint8]                $n # const unsigned char*
                             ,Pointer[uint8]                $k # const unsigned char*
                              ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_stream_salsa20.h:36
    #SODIUM_EXPORT
    #int crypto_stream_salsa20_xor(unsigned char *c, const unsigned char *m,
    sub crypto_stream_salsa20_xor(Pointer[uint8]                $c # unsigned char*
                                 ,Pointer[uint8]                $m # const unsigned char*
                                 ,ulonglong                     $mlen # long long unsigned int
                                 ,Pointer[uint8]                $n # const unsigned char*
                                 ,Pointer[uint8]                $k # const unsigned char*
                                  ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_stream_salsa20.h:41
    #SODIUM_EXPORT
    #int crypto_stream_salsa20_xor_ic(unsigned char *c, const unsigned char *m,
    sub crypto_stream_salsa20_xor_ic(Pointer[uint8]                $c # unsigned char*
                                    ,Pointer[uint8]                $m # const unsigned char*
                                    ,ulonglong                     $mlen # long long unsigned int
                                    ,Pointer[uint8]                $n # const unsigned char*
                                    ,uint64                      $ic # Typedef<uint64>->|long unsigned int|
                                    ,Pointer[uint8]                $k # const unsigned char*
                                     ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_scalarmult_curve25519.h ==

    #-From /usr/include/sodium/crypto_scalarmult_curve25519.h:14
    ##define crypto_scalarmult_curve25519_BYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_scalarmult_curve25519_bytes(void);
    sub crypto_scalarmult_curve25519_bytes(
                                           ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_scalarmult_curve25519.h:18
    ##define crypto_scalarmult_curve25519_SCALARBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_scalarmult_curve25519_scalarbytes(void);
    sub crypto_scalarmult_curve25519_scalarbytes(
                                                 ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_scalarmult_curve25519.h:21
    #SODIUM_EXPORT
    #int crypto_scalarmult_curve25519(unsigned char *q, const unsigned char *n,
    sub crypto_scalarmult_curve25519(Pointer[uint8]                $q # unsigned char*
                                    ,Pointer[uint8]                $n # const unsigned char*
                                    ,Pointer[uint8]                $p # const unsigned char*
                                     ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_scalarmult_curve25519.h:26
    #SODIUM_EXPORT
    #int crypto_scalarmult_curve25519_base(unsigned char *q, const unsigned char *n);
    sub crypto_scalarmult_curve25519_base(Pointer[uint8]                $q # unsigned char*
                                         ,Pointer[uint8]                $n # const unsigned char*
                                          ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_scalarmult_curve25519.h:30
    #int _crypto_scalarmult_curve25519_pick_best_implementation(void);
    sub _crypto_scalarmult_curve25519_pick_best_implementation(
                                                               ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_hash_sha256.h ==

    #-From /usr/include/sodium/crypto_hash_sha256.h:30
    #SODIUM_EXPORT
    #size_t crypto_hash_sha256_statebytes(void);
    sub crypto_hash_sha256_statebytes(
                                      ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_hash_sha256.h:34
    ##define crypto_hash_sha256_BYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_hash_sha256_bytes(void);
    sub crypto_hash_sha256_bytes(
                                 ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_hash_sha256.h:37
    #SODIUM_EXPORT
    #int crypto_hash_sha256(unsigned char *out, const unsigned char *in,
    sub crypto_hash_sha256(Pointer[uint8]                $out # unsigned char*
                          ,Pointer[uint8]                $in # const unsigned char*
                          ,ulonglong                     $inlen # long long unsigned int
                           ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_hash_sha256.h:41
    #SODIUM_EXPORT
    #int crypto_hash_sha256_init(crypto_hash_sha256_state *state);
    sub crypto_hash_sha256_init(crypto_hash_sha256_state $state # Typedef<crypto_hash_sha256_state>->|crypto_hash_sha256_state|*
                                ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_hash_sha256.h:44
    #SODIUM_EXPORT
    #int crypto_hash_sha256_update(crypto_hash_sha256_state *state,
    sub crypto_hash_sha256_update(crypto_hash_sha256_state      $state # Typedef<crypto_hash_sha256_state>->|crypto_hash_sha256_state|*
                                 ,Pointer[uint8]                $in # const unsigned char*
                                 ,ulonglong                     $inlen # long long unsigned int
                                  ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_hash_sha256.h:49
    #SODIUM_EXPORT
    #int crypto_hash_sha256_final(crypto_hash_sha256_state *state,
    sub crypto_hash_sha256_final(crypto_hash_sha256_state      $state # Typedef<crypto_hash_sha256_state>->|crypto_hash_sha256_state|*
                                ,Pointer[uint8]                $out # unsigned char*
                                 ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_hash_sha512.h ==

    #-From /usr/include/sodium/crypto_hash_sha512.h:30
    #SODIUM_EXPORT
    #size_t crypto_hash_sha512_statebytes(void);
    sub crypto_hash_sha512_statebytes(
                                      ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_hash_sha512.h:34
    ##define crypto_hash_sha512_BYTES 64U
    #SODIUM_EXPORT
    #size_t crypto_hash_sha512_bytes(void);
    sub crypto_hash_sha512_bytes(
                                 ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_hash_sha512.h:37
    #SODIUM_EXPORT
    #int crypto_hash_sha512(unsigned char *out, const unsigned char *in,
    sub crypto_hash_sha512(Pointer[uint8]                $out # unsigned char*
                          ,Pointer[uint8]                $in # const unsigned char*
                          ,ulonglong                     $inlen # long long unsigned int
                           ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_hash_sha512.h:41
    #SODIUM_EXPORT
    #int crypto_hash_sha512_init(crypto_hash_sha512_state *state);
    sub crypto_hash_sha512_init(crypto_hash_sha512_state $state # Typedef<crypto_hash_sha512_state>->|crypto_hash_sha512_state|*
                                ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_hash_sha512.h:44
    #SODIUM_EXPORT
    #int crypto_hash_sha512_update(crypto_hash_sha512_state *state,
    sub crypto_hash_sha512_update(crypto_hash_sha512_state      $state # Typedef<crypto_hash_sha512_state>->|crypto_hash_sha512_state|*
                                 ,Pointer[uint8]                $in # const unsigned char*
                                 ,ulonglong                     $inlen # long long unsigned int
                                  ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_hash_sha512.h:49
    #SODIUM_EXPORT
    #int crypto_hash_sha512_final(crypto_hash_sha512_state *state,
    sub crypto_hash_sha512_final(crypto_hash_sha512_state      $state # Typedef<crypto_hash_sha512_state>->|crypto_hash_sha512_state|*
                                ,Pointer[uint8]                $out # unsigned char*
                                 ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_pwhash_scryptsalsa208sha256.h ==

    #-From /usr/include/sodium/crypto_pwhash_scryptsalsa208sha256.h:18
    ##define crypto_pwhash_scryptsalsa208sha256_SALTBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_pwhash_scryptsalsa208sha256_saltbytes(void);
    sub crypto_pwhash_scryptsalsa208sha256_saltbytes(
                                                     ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_pwhash_scryptsalsa208sha256.h:22
    ##define crypto_pwhash_scryptsalsa208sha256_STRBYTES 102U
    #SODIUM_EXPORT
    #size_t crypto_pwhash_scryptsalsa208sha256_strbytes(void);
    sub crypto_pwhash_scryptsalsa208sha256_strbytes(
                                                    ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_pwhash_scryptsalsa208sha256.h:26
    ##define crypto_pwhash_scryptsalsa208sha256_STRPREFIX "$7$"
    #SODIUM_EXPORT
    #const char *crypto_pwhash_scryptsalsa208sha256_strprefix(void);
    sub crypto_pwhash_scryptsalsa208sha256_strprefix(
                                                     ) is native(LIB) returns Str { * }

    #-From /usr/include/sodium/crypto_pwhash_scryptsalsa208sha256.h:30
    ##define crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE 524288ULL
    #SODIUM_EXPORT
    #size_t crypto_pwhash_scryptsalsa208sha256_opslimit_interactive(void);
    sub crypto_pwhash_scryptsalsa208sha256_opslimit_interactive(
                                                                ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_pwhash_scryptsalsa208sha256.h:34
    ##define crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE 16777216ULL
    #SODIUM_EXPORT
    #size_t crypto_pwhash_scryptsalsa208sha256_memlimit_interactive(void);
    sub crypto_pwhash_scryptsalsa208sha256_memlimit_interactive(
                                                                ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_pwhash_scryptsalsa208sha256.h:38
    ##define crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE 33554432ULL
    #SODIUM_EXPORT
    #size_t crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive(void);
    sub crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive(
                                                              ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_pwhash_scryptsalsa208sha256.h:42
    ##define crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE 1073741824ULL
    #SODIUM_EXPORT
    #size_t crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive(void);
    sub crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive(
                                                              ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_pwhash_scryptsalsa208sha256.h:45
    #SODIUM_EXPORT
    #int crypto_pwhash_scryptsalsa208sha256(unsigned char * const out,
    sub crypto_pwhash_scryptsalsa208sha256(Pointer[uint8]                $out # const unsigned char*
                                          ,ulonglong                     $outlen # long long unsigned int
                                          ,Str                           $passwd # const const char*
                                          ,ulonglong                     $passwdlen # long long unsigned int
                                          ,Pointer[uint8]                $salt # const const unsigned char*
                                          ,ulonglong                     $opslimit # long long unsigned int
                                          ,size_t                        $memlimit # Typedef<size_t>->|long unsigned int|
                                           ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_pwhash_scryptsalsa208sha256.h:55
    #SODIUM_EXPORT
    #int crypto_pwhash_scryptsalsa208sha256_str(char out[crypto_pwhash_scryptsalsa208sha256_STRBYTES],
    sub crypto_pwhash_scryptsalsa208sha256_str(Str                           $out # char*
                                              ,Str                           $passwd # const const char*
                                              ,ulonglong                     $passwdlen # long long unsigned int
                                              ,ulonglong                     $opslimit # long long unsigned int
                                              ,size_t                        $memlimit # Typedef<size_t>->|long unsigned int|
                                               ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_pwhash_scryptsalsa208sha256.h:63
    #SODIUM_EXPORT
    #int crypto_pwhash_scryptsalsa208sha256_str_verify(const char str[crypto_pwhash_scryptsalsa208sha256_STRBYTES],
    sub crypto_pwhash_scryptsalsa208sha256_str_verify(Str                           $str # const char*
                                                     ,Str                           $passwd # const const char*
                                                     ,ulonglong                     $passwdlen # long long unsigned int
                                                      ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_pwhash_scryptsalsa208sha256.h:69
    #SODIUM_EXPORT
    #int crypto_pwhash_scryptsalsa208sha256_ll(const uint8 * passwd, size_t passwdlen,
    sub crypto_pwhash_scryptsalsa208sha256_ll(Pointer[uint8]              $passwd # const Typedef<uint8>->|unsigned char|*
                                             ,size_t                        $passwdlen # Typedef<size_t>->|long unsigned int|
                                             ,Pointer[uint8]              $salt # const Typedef<uint8>->|unsigned char|*
                                             ,size_t                        $saltlen # Typedef<size_t>->|long unsigned int|
                                             ,uint64                      $N # Typedef<uint64>->|long unsigned int|
                                             ,uint32                      $r # Typedef<uint32>->|unsigned int|
                                             ,uint32                      $p # Typedef<uint32>->|unsigned int|
                                             ,Pointer[uint8]              $buf # Typedef<uint8>->|unsigned char|*
                                             ,size_t                        $buflen # Typedef<size_t>->|long unsigned int|
                                              ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_auth.h ==

    #-From /usr/include/sodium/crypto_auth.h:18
    ##define crypto_auth_BYTES crypto_auth_hmacsha512256_BYTES
    #SODIUM_EXPORT
    #size_t  crypto_auth_bytes(void);
    sub crypto_auth_bytes(
                          ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_auth.h:22
    ##define crypto_auth_KEYBYTES crypto_auth_hmacsha512256_KEYBYTES
    #SODIUM_EXPORT
    #size_t  crypto_auth_keybytes(void);
    sub crypto_auth_keybytes(
                             ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_auth.h:26
    ##define crypto_auth_PRIMITIVE "hmacsha512256"
    #SODIUM_EXPORT
    #const char *crypto_auth_primitive(void);
    sub crypto_auth_primitive(
                              ) is native(LIB) returns Str { * }

    #-From /usr/include/sodium/crypto_auth.h:29
    #SODIUM_EXPORT
    #int crypto_auth(unsigned char *out, const unsigned char *in,
    sub crypto_auth(Pointer[uint8]                $out # unsigned char*
                   ,Pointer[uint8]                $in # const unsigned char*
                   ,ulonglong                     $inlen # long long unsigned int
                   ,Pointer[uint8]                $k # const unsigned char*
                    ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_auth.h:33
    #SODIUM_EXPORT
    #int crypto_auth_verify(const unsigned char *h, const unsigned char *in,
    sub crypto_auth_verify(Pointer[uint8]                $h # const unsigned char*
                          ,Pointer[uint8]                $in # const unsigned char*
                          ,ulonglong                     $inlen # long long unsigned int
                          ,Pointer[uint8]                $k # const unsigned char*
                           ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_auth_hmacsha512256.h ==

    #-From /usr/include/sodium/crypto_auth_hmacsha512256.h:17
    ##define crypto_auth_hmacsha512256_BYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_auth_hmacsha512256_bytes(void);
    sub crypto_auth_hmacsha512256_bytes(
                                        ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_auth_hmacsha512256.h:21
    ##define crypto_auth_hmacsha512256_KEYBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_auth_hmacsha512256_keybytes(void);
    sub crypto_auth_hmacsha512256_keybytes(
                                           ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_auth_hmacsha512256.h:24
    #SODIUM_EXPORT
    #int crypto_auth_hmacsha512256(unsigned char *out, const unsigned char *in,
    sub crypto_auth_hmacsha512256(Pointer[uint8]                $out # unsigned char*
                                 ,Pointer[uint8]                $in # const unsigned char*
                                 ,ulonglong                     $inlen # long long unsigned int
                                 ,Pointer[uint8]                $k # const unsigned char*
                                  ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_auth_hmacsha512256.h:28
    #SODIUM_EXPORT
    #int crypto_auth_hmacsha512256_verify(const unsigned char *h,
    sub crypto_auth_hmacsha512256_verify(Pointer[uint8]                $h # const unsigned char*
                                        ,Pointer[uint8]                $in # const unsigned char*
                                        ,ulonglong                     $inlen # long long unsigned int
                                        ,Pointer[uint8]                $k # const unsigned char*
                                         ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_auth_hmacsha512256.h:38
    #SODIUM_EXPORT
    #size_t crypto_auth_hmacsha512256_statebytes(void);
    sub crypto_auth_hmacsha512256_statebytes(
                                             ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_auth_hmacsha512256.h:41
    #SODIUM_EXPORT
    #int crypto_auth_hmacsha512256_init(crypto_auth_hmacsha512256_state *state,
    sub crypto_auth_hmacsha512256_init(Pointer[crypto_auth_hmacsha512_state]$state # Typedef<crypto_auth_hmacsha512256_state>->|Typedef<crypto_auth_hmacsha512_state>->|crypto_auth_hmacsha512_state||*
                                      ,Pointer[uint8]                $key # const unsigned char*
                                      ,size_t                        $keylen # Typedef<size_t>->|long unsigned int|
                                       ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_auth_hmacsha512256.h:46
    #SODIUM_EXPORT
    #int crypto_auth_hmacsha512256_update(crypto_auth_hmacsha512256_state *state,
    sub crypto_auth_hmacsha512256_update(Pointer[crypto_auth_hmacsha512_state]$state # Typedef<crypto_auth_hmacsha512256_state>->|Typedef<crypto_auth_hmacsha512_state>->|crypto_auth_hmacsha512_state||*
                                        ,Pointer[uint8]                $in # const unsigned char*
                                        ,ulonglong                     $inlen # long long unsigned int
                                         ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_auth_hmacsha512256.h:51
    #SODIUM_EXPORT
    #int crypto_auth_hmacsha512256_final(crypto_auth_hmacsha512256_state *state,
    sub crypto_auth_hmacsha512256_final(Pointer[crypto_auth_hmacsha512_state]$state # Typedef<crypto_auth_hmacsha512256_state>->|Typedef<crypto_auth_hmacsha512_state>->|crypto_auth_hmacsha512_state||*
                                       ,Pointer[uint8]                $out # unsigned char*
                                        ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_scalarmult.h ==

    #-From /usr/include/sodium/crypto_scalarmult.h:15
    ##define crypto_scalarmult_BYTES crypto_scalarmult_curve25519_BYTES
    #SODIUM_EXPORT
    #size_t  crypto_scalarmult_bytes(void);
    sub crypto_scalarmult_bytes(
                                ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_scalarmult.h:19
    ##define crypto_scalarmult_SCALARBYTES crypto_scalarmult_curve25519_SCALARBYTES
    #SODIUM_EXPORT
    #size_t  crypto_scalarmult_scalarbytes(void);
    sub crypto_scalarmult_scalarbytes(
                                      ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_scalarmult.h:23
    ##define crypto_scalarmult_PRIMITIVE "curve25519"
    #SODIUM_EXPORT
    #const char *crypto_scalarmult_primitive(void);
    sub crypto_scalarmult_primitive(
                                    ) is native(LIB) returns Str { * }

    #-From /usr/include/sodium/crypto_scalarmult.h:26
    #SODIUM_EXPORT
    #int crypto_scalarmult_base(unsigned char *q, const unsigned char *n);
    sub crypto_scalarmult_base(Pointer[uint8]                $q # unsigned char*
                              ,Pointer[uint8]                $n # const unsigned char*
                               ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_scalarmult.h:29
    #SODIUM_EXPORT
    #int crypto_scalarmult(unsigned char *q, const unsigned char *n,
    sub crypto_scalarmult(Pointer[uint8]                $q # unsigned char*
                         ,Pointer[uint8]                $n # const unsigned char*
                         ,Pointer[uint8]                $p # const unsigned char*
                          ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_box_curve25519xsalsa20poly1305.h ==

    #-From /usr/include/sodium/crypto_box_curve25519xsalsa20poly1305.h:16
    ##define crypto_box_curve25519xsalsa20poly1305_SEEDBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_box_curve25519xsalsa20poly1305_seedbytes(void);
    sub crypto_box_curve25519xsalsa20poly1305_seedbytes(
                                                        ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_box_curve25519xsalsa20poly1305.h:20
    ##define crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_box_curve25519xsalsa20poly1305_publickeybytes(void);
    sub crypto_box_curve25519xsalsa20poly1305_publickeybytes(
                                                             ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_box_curve25519xsalsa20poly1305.h:24
    ##define crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_box_curve25519xsalsa20poly1305_secretkeybytes(void);
    sub crypto_box_curve25519xsalsa20poly1305_secretkeybytes(
                                                             ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_box_curve25519xsalsa20poly1305.h:28
    ##define crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_box_curve25519xsalsa20poly1305_beforenmbytes(void);
    sub crypto_box_curve25519xsalsa20poly1305_beforenmbytes(
                                                            ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_box_curve25519xsalsa20poly1305.h:32
    ##define crypto_box_curve25519xsalsa20poly1305_NONCEBYTES 24U
    #SODIUM_EXPORT
    #size_t crypto_box_curve25519xsalsa20poly1305_noncebytes(void);
    sub crypto_box_curve25519xsalsa20poly1305_noncebytes(
                                                         ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_box_curve25519xsalsa20poly1305.h:36
    ##define crypto_box_curve25519xsalsa20poly1305_ZEROBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_box_curve25519xsalsa20poly1305_zerobytes(void);
    sub crypto_box_curve25519xsalsa20poly1305_zerobytes(
                                                        ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_box_curve25519xsalsa20poly1305.h:40
    ##define crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES 16U
    #SODIUM_EXPORT
    #size_t crypto_box_curve25519xsalsa20poly1305_boxzerobytes(void);
    sub crypto_box_curve25519xsalsa20poly1305_boxzerobytes(
                                                           ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_box_curve25519xsalsa20poly1305.h:46
    ##define crypto_box_curve25519xsalsa20poly1305_MACBYTES \
    #    (crypto_box_curve25519xsalsa20poly1305_ZEROBYTES - \
    #     crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES)
    #SODIUM_EXPORT
    #size_t crypto_box_curve25519xsalsa20poly1305_macbytes(void);
    sub crypto_box_curve25519xsalsa20poly1305_macbytes(
                                                       ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_box_curve25519xsalsa20poly1305.h:49
    #SODIUM_EXPORT
    #int crypto_box_curve25519xsalsa20poly1305(unsigned char *c,
    sub crypto_box_curve25519xsalsa20poly1305(Pointer[uint8]                $c # unsigned char*
                                             ,Pointer[uint8]                $m # const unsigned char*
                                             ,ulonglong                     $mlen # long long unsigned int
                                             ,Pointer[uint8]                $n # const unsigned char*
                                             ,Pointer[uint8]                $pk # const unsigned char*
                                             ,Pointer[uint8]                $sk # const unsigned char*
                                              ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_box_curve25519xsalsa20poly1305.h:58
    #SODIUM_EXPORT
    #int crypto_box_curve25519xsalsa20poly1305_open(unsigned char *m,
    sub crypto_box_curve25519xsalsa20poly1305_open(Pointer[uint8]                $m # unsigned char*
                                                  ,Pointer[uint8]                $c # const unsigned char*
                                                  ,ulonglong                     $clen # long long unsigned int
                                                  ,Pointer[uint8]                $n # const unsigned char*
                                                  ,Pointer[uint8]                $pk # const unsigned char*
                                                  ,Pointer[uint8]                $sk # const unsigned char*
                                                   ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_box_curve25519xsalsa20poly1305.h:67
    #SODIUM_EXPORT
    #int crypto_box_curve25519xsalsa20poly1305_seed_keypair(unsigned char *pk,
    sub crypto_box_curve25519xsalsa20poly1305_seed_keypair(Pointer[uint8]                $pk # unsigned char*
                                                          ,Pointer[uint8]                $sk # unsigned char*
                                                          ,Pointer[uint8]                $seed # const unsigned char*
                                                           ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_box_curve25519xsalsa20poly1305.h:72
    #SODIUM_EXPORT
    #int crypto_box_curve25519xsalsa20poly1305_keypair(unsigned char *pk,
    sub crypto_box_curve25519xsalsa20poly1305_keypair(Pointer[uint8]                $pk # unsigned char*
                                                     ,Pointer[uint8]                $sk # unsigned char*
                                                      ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_box_curve25519xsalsa20poly1305.h:76
    #SODIUM_EXPORT
    #int crypto_box_curve25519xsalsa20poly1305_beforenm(unsigned char *k,
    sub crypto_box_curve25519xsalsa20poly1305_beforenm(Pointer[uint8]                $k # unsigned char*
                                                      ,Pointer[uint8]                $pk # const unsigned char*
                                                      ,Pointer[uint8]                $sk # const unsigned char*
                                                       ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_box_curve25519xsalsa20poly1305.h:82
    #SODIUM_EXPORT
    #int crypto_box_curve25519xsalsa20poly1305_afternm(unsigned char *c,
    sub crypto_box_curve25519xsalsa20poly1305_afternm(Pointer[uint8]                $c # unsigned char*
                                                     ,Pointer[uint8]                $m # const unsigned char*
                                                     ,ulonglong                     $mlen # long long unsigned int
                                                     ,Pointer[uint8]                $n # const unsigned char*
                                                     ,Pointer[uint8]                $k # const unsigned char*
                                                      ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_box_curve25519xsalsa20poly1305.h:89
    #SODIUM_EXPORT
    #int crypto_box_curve25519xsalsa20poly1305_open_afternm(unsigned char *m,
    sub crypto_box_curve25519xsalsa20poly1305_open_afternm(Pointer[uint8]                $m # unsigned char*
                                                          ,Pointer[uint8]                $c # const unsigned char*
                                                          ,ulonglong                     $clen # long long unsigned int
                                                          ,Pointer[uint8]                $n # const unsigned char*
                                                          ,Pointer[uint8]                $k # const unsigned char*
                                                           ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_secretbox_xsalsa20poly1305.h ==

    #-From /usr/include/sodium/crypto_secretbox_xsalsa20poly1305.h:16
    ##define crypto_secretbox_xsalsa20poly1305_KEYBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_secretbox_xsalsa20poly1305_keybytes(void);
    sub crypto_secretbox_xsalsa20poly1305_keybytes(
                                                   ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_secretbox_xsalsa20poly1305.h:20
    ##define crypto_secretbox_xsalsa20poly1305_NONCEBYTES 24U
    #SODIUM_EXPORT
    #size_t crypto_secretbox_xsalsa20poly1305_noncebytes(void);
    sub crypto_secretbox_xsalsa20poly1305_noncebytes(
                                                     ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_secretbox_xsalsa20poly1305.h:24
    ##define crypto_secretbox_xsalsa20poly1305_ZEROBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_secretbox_xsalsa20poly1305_zerobytes(void);
    sub crypto_secretbox_xsalsa20poly1305_zerobytes(
                                                    ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_secretbox_xsalsa20poly1305.h:28
    ##define crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES 16U
    #SODIUM_EXPORT
    #size_t crypto_secretbox_xsalsa20poly1305_boxzerobytes(void);
    sub crypto_secretbox_xsalsa20poly1305_boxzerobytes(
                                                       ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_secretbox_xsalsa20poly1305.h:34
    ##define crypto_secretbox_xsalsa20poly1305_MACBYTES \
    #    (crypto_secretbox_xsalsa20poly1305_ZEROBYTES - \
    #     crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES)
    #SODIUM_EXPORT
    #size_t crypto_secretbox_xsalsa20poly1305_macbytes(void);
    sub crypto_secretbox_xsalsa20poly1305_macbytes(
                                                   ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_secretbox_xsalsa20poly1305.h:37
    #SODIUM_EXPORT
    #int crypto_secretbox_xsalsa20poly1305(unsigned char *c,
    sub crypto_secretbox_xsalsa20poly1305(Pointer[uint8]                $c # unsigned char*
                                         ,Pointer[uint8]                $m # const unsigned char*
                                         ,ulonglong                     $mlen # long long unsigned int
                                         ,Pointer[uint8]                $n # const unsigned char*
                                         ,Pointer[uint8]                $k # const unsigned char*
                                          ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_secretbox_xsalsa20poly1305.h:44
    #SODIUM_EXPORT
    #int crypto_secretbox_xsalsa20poly1305_open(unsigned char *m,
    sub crypto_secretbox_xsalsa20poly1305_open(Pointer[uint8]                $m # unsigned char*
                                              ,Pointer[uint8]                $c # const unsigned char*
                                              ,ulonglong                     $clen # long long unsigned int
                                              ,Pointer[uint8]                $n # const unsigned char*
                                              ,Pointer[uint8]                $k # const unsigned char*
                                               ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_stream.h ==

    #-From /usr/include/sodium/crypto_stream.h:26
    ##define crypto_stream_KEYBYTES crypto_stream_xsalsa20_KEYBYTES
    #SODIUM_EXPORT
    #size_t  crypto_stream_keybytes(void);
    sub crypto_stream_keybytes(
                               ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_stream.h:30
    ##define crypto_stream_NONCEBYTES crypto_stream_xsalsa20_NONCEBYTES
    #SODIUM_EXPORT
    #size_t  crypto_stream_noncebytes(void);
    sub crypto_stream_noncebytes(
                                 ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_stream.h:34
    ##define crypto_stream_PRIMITIVE "xsalsa20"
    #SODIUM_EXPORT
    #const char *crypto_stream_primitive(void);
    sub crypto_stream_primitive(
                                ) is native(LIB) returns Str { * }

    #-From /usr/include/sodium/crypto_stream.h:37
    #SODIUM_EXPORT
    #int crypto_stream(unsigned char *c, unsigned long long clen,
    sub crypto_stream(Pointer[uint8]                $c # unsigned char*
                     ,ulonglong                     $clen # long long unsigned int
                     ,Pointer[uint8]                $n # const unsigned char*
                     ,Pointer[uint8]                $k # const unsigned char*
                      ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_stream.h:41
    #SODIUM_EXPORT
    #int crypto_stream_xor(unsigned char *c, const unsigned char *m,
    sub crypto_stream_xor(Pointer[uint8]                $c # unsigned char*
                         ,Pointer[uint8]                $m # const unsigned char*
                         ,ulonglong                     $mlen # long long unsigned int
                         ,Pointer[uint8]                $n # const unsigned char*
                         ,Pointer[uint8]                $k # const unsigned char*
                          ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/version.h ==

    #-From /usr/include/sodium/version.h:17
    #SODIUM_EXPORT
    #const char *sodium_version_string(void);
    sub sodium_version_string(
                              ) is native(LIB) returns Str { * }

    #-From /usr/include/sodium/version.h:20
    #SODIUM_EXPORT
    #int         sodium_library_version_major(void);
    sub sodium_library_version_major(
                                     ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/version.h:23
    #SODIUM_EXPORT
    #int         sodium_library_version_minor(void);
    sub sodium_library_version_minor(
                                     ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_hash.h ==

    #-From /usr/include/sodium/crypto_hash.h:25
    ##define crypto_hash_BYTES crypto_hash_sha512_BYTES
    #SODIUM_EXPORT
    #size_t crypto_hash_bytes(void);
    sub crypto_hash_bytes(
                          ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_hash.h:28
    #SODIUM_EXPORT
    #int crypto_hash(unsigned char *out, const unsigned char *in,
    sub crypto_hash(Pointer[uint8]                $out # unsigned char*
                   ,Pointer[uint8]                $in # const unsigned char*
                   ,ulonglong                     $inlen # long long unsigned int
                    ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_hash.h:33
    ##define crypto_hash_PRIMITIVE "sha512"
    #SODIUM_EXPORT
    #const char *crypto_hash_primitive(void)
    sub crypto_hash_primitive(
                              ) is native(LIB) returns Str { * }


    # == /usr/include/sodium/crypto_sign_ed25519.h ==

    #-From /usr/include/sodium/crypto_sign_ed25519.h:16
    ##define crypto_sign_ed25519_BYTES 64U
    #SODIUM_EXPORT
    #size_t crypto_sign_ed25519_bytes(void);
    sub crypto_sign_ed25519_bytes(
                                  ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_sign_ed25519.h:20
    ##define crypto_sign_ed25519_SEEDBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_sign_ed25519_seedbytes(void);
    sub crypto_sign_ed25519_seedbytes(
                                      ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_sign_ed25519.h:24
    ##define crypto_sign_ed25519_PUBLICKEYBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_sign_ed25519_publickeybytes(void);
    sub crypto_sign_ed25519_publickeybytes(
                                           ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_sign_ed25519.h:28
    ##define crypto_sign_ed25519_SECRETKEYBYTES (32U + 32U)
    #SODIUM_EXPORT
    #size_t crypto_sign_ed25519_secretkeybytes(void);
    sub crypto_sign_ed25519_secretkeybytes(
                                           ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_sign_ed25519.h:31
    #SODIUM_EXPORT
    #int crypto_sign_ed25519(unsigned char *sm, unsigned long long *smlen_p,
    sub crypto_sign_ed25519(Pointer[uint8]                $sm # unsigned char*
                           ,Pointer[ulonglong]            $smlen_p # long long unsigned int*
                           ,Pointer[uint8]                $m # const unsigned char*
                           ,ulonglong                     $mlen # long long unsigned int
                           ,Pointer[uint8]                $sk # const unsigned char*
                            ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_sign_ed25519.h:36
    #SODIUM_EXPORT
    #int crypto_sign_ed25519_open(unsigned char *m, unsigned long long *mlen_p,
    sub crypto_sign_ed25519_open(Pointer[uint8]                $m # unsigned char*
                                ,Pointer[ulonglong]            $mlen_p # long long unsigned int*
                                ,Pointer[uint8]                $sm # const unsigned char*
                                ,ulonglong                     $smlen # long long unsigned int
                                ,Pointer[uint8]                $pk # const unsigned char*
                                 ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_sign_ed25519.h:42
    #SODIUM_EXPORT
    #int crypto_sign_ed25519_detached(unsigned char *sig,
    sub crypto_sign_ed25519_detached(Pointer[uint8]                $sig # unsigned char*
                                    ,Pointer[ulonglong]            $siglen_p # long long unsigned int*
                                    ,Pointer[uint8]                $m # const unsigned char*
                                    ,ulonglong                     $mlen # long long unsigned int
                                    ,Pointer[uint8]                $sk # const unsigned char*
                                     ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_sign_ed25519.h:49
    #SODIUM_EXPORT
    #int crypto_sign_ed25519_verify_detached(const unsigned char *sig,
    sub crypto_sign_ed25519_verify_detached(Pointer[uint8]                $sig # const unsigned char*
                                           ,Pointer[uint8]                $m # const unsigned char*
                                           ,ulonglong                     $mlen # long long unsigned int
                                           ,Pointer[uint8]                $pk # const unsigned char*
                                            ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_sign_ed25519.h:56
    #SODIUM_EXPORT
    #int crypto_sign_ed25519_keypair(unsigned char *pk, unsigned char *sk);
    sub crypto_sign_ed25519_keypair(Pointer[uint8]                $pk # unsigned char*
                                   ,Pointer[uint8]                $sk # unsigned char*
                                    ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_sign_ed25519.h:59
    #SODIUM_EXPORT
    #int crypto_sign_ed25519_seed_keypair(unsigned char *pk, unsigned char *sk,
    sub crypto_sign_ed25519_seed_keypair(Pointer[uint8]                $pk # unsigned char*
                                        ,Pointer[uint8]                $sk # unsigned char*
                                        ,Pointer[uint8]                $seed # const unsigned char*
                                         ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_sign_ed25519.h:63
    #SODIUM_EXPORT
    #int crypto_sign_ed25519_pk_to_curve25519(unsigned char *curve25519_pk,
    sub crypto_sign_ed25519_pk_to_curve25519(Pointer[uint8]                $curve25519_pk # unsigned char*
                                            ,Pointer[uint8]                $ed25519_pk # const unsigned char*
                                             ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_sign_ed25519.h:68
    #SODIUM_EXPORT
    #int crypto_sign_ed25519_sk_to_curve25519(unsigned char *curve25519_sk,
    sub crypto_sign_ed25519_sk_to_curve25519(Pointer[uint8]                $curve25519_sk # unsigned char*
                                            ,Pointer[uint8]                $ed25519_sk # const unsigned char*
                                             ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_sign_ed25519.h:72
    #SODIUM_EXPORT
    #int crypto_sign_ed25519_sk_to_seed(unsigned char *seed,
    sub crypto_sign_ed25519_sk_to_seed(Pointer[uint8]                $seed # unsigned char*
                                      ,Pointer[uint8]                $sk # const unsigned char*
                                       ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_sign_ed25519.h:76
    #SODIUM_EXPORT
    #int crypto_sign_ed25519_sk_to_pk(unsigned char *pk, const unsigned char *sk);
    sub crypto_sign_ed25519_sk_to_pk(Pointer[uint8]                $pk # unsigned char*
                                    ,Pointer[uint8]                $sk # const unsigned char*
                                     ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_shorthash.h ==

    #-From /usr/include/sodium/crypto_shorthash.h:18
    ##define crypto_shorthash_BYTES crypto_shorthash_siphash24_BYTES
    #SODIUM_EXPORT
    #size_t  crypto_shorthash_bytes(void);
    sub crypto_shorthash_bytes(
                               ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_shorthash.h:22
    ##define crypto_shorthash_KEYBYTES crypto_shorthash_siphash24_KEYBYTES
    #SODIUM_EXPORT
    #size_t  crypto_shorthash_keybytes(void);
    sub crypto_shorthash_keybytes(
                                  ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_shorthash.h:26
    ##define crypto_shorthash_PRIMITIVE "siphash24"
    #SODIUM_EXPORT
    #const char *crypto_shorthash_primitive(void);
    sub crypto_shorthash_primitive(
                                   ) is native(LIB) returns Str { * }

    #-From /usr/include/sodium/crypto_shorthash.h:29
    #SODIUM_EXPORT
    #int crypto_shorthash(unsigned char *out, const unsigned char *in,
    sub crypto_shorthash(Pointer[uint8]                $out # unsigned char*
                        ,Pointer[uint8]                $in # const unsigned char*
                        ,ulonglong                     $inlen # long long unsigned int
                        ,Pointer[uint8]                $k # const unsigned char*
                         ) is native(LIB) returns int32 { * }



    # == /usr/include/sodium/crypto_onetimeauth.h ==

    #-From /usr/include/sodium/crypto_onetimeauth.h:18
    #SODIUM_EXPORT
    #size_t  crypto_onetimeauth_statebytes(void);
    sub crypto_onetimeauth_statebytes(
                                      ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_onetimeauth.h:22
    ##define crypto_onetimeauth_BYTES crypto_onetimeauth_poly1305_BYTES
    #SODIUM_EXPORT
    #size_t  crypto_onetimeauth_bytes(void);
    sub crypto_onetimeauth_bytes(
                                 ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_onetimeauth.h:26
    ##define crypto_onetimeauth_KEYBYTES crypto_onetimeauth_poly1305_KEYBYTES
    #SODIUM_EXPORT
    #size_t  crypto_onetimeauth_keybytes(void);
    sub crypto_onetimeauth_keybytes(
                                    ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_onetimeauth.h:30
    ##define crypto_onetimeauth_PRIMITIVE "poly1305"
    #SODIUM_EXPORT
    #const char *crypto_onetimeauth_primitive(void);
    sub crypto_onetimeauth_primitive(
                                     ) is native(LIB) returns Str { * }

    #-From /usr/include/sodium/crypto_onetimeauth.h:33
    #SODIUM_EXPORT
    #int crypto_onetimeauth(unsigned char *out, const unsigned char *in,
    sub crypto_onetimeauth(Pointer[uint8]                $out # unsigned char*
                          ,Pointer[uint8]                $in # const unsigned char*
                          ,ulonglong                     $inlen # long long unsigned int
                          ,Pointer[uint8]                $k # const unsigned char*
                           ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_onetimeauth.h:37
    #SODIUM_EXPORT
    #int crypto_onetimeauth_verify(const unsigned char *h, const unsigned char *in,
    sub crypto_onetimeauth_verify(Pointer[uint8]                $h # const unsigned char*
                                 ,Pointer[uint8]                $in # const unsigned char*
                                 ,ulonglong                     $inlen # long long unsigned int
                                 ,Pointer[uint8]                $k # const unsigned char*
                                  ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_onetimeauth.h:42
    #SODIUM_EXPORT
    #int crypto_onetimeauth_init(crypto_onetimeauth_state *state,
    sub crypto_onetimeauth_init(Pointer[crypto_onetimeauth_poly1305_state]$state # Typedef<crypto_onetimeauth_state>->|Typedef<crypto_onetimeauth_poly1305_state>->|crypto_onetimeauth_poly1305_state||*
                               ,Pointer[uint8]                $key # const unsigned char*
                                ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_onetimeauth.h:46
    #SODIUM_EXPORT
    #int crypto_onetimeauth_update(crypto_onetimeauth_state *state,
    sub crypto_onetimeauth_update(Pointer[crypto_onetimeauth_poly1305_state]$state # Typedef<crypto_onetimeauth_state>->|Typedef<crypto_onetimeauth_poly1305_state>->|crypto_onetimeauth_poly1305_state||*
                                 ,Pointer[uint8]                $in # const unsigned char*
                                 ,ulonglong                     $inlen # long long unsigned int
                                  ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_onetimeauth.h:51
    #SODIUM_EXPORT
    #int crypto_onetimeauth_final(crypto_onetimeauth_state *state,
    sub crypto_onetimeauth_final(Pointer[crypto_onetimeauth_poly1305_state]$state # Typedef<crypto_onetimeauth_state>->|Typedef<crypto_onetimeauth_poly1305_state>->|crypto_onetimeauth_poly1305_state||*
                                ,Pointer[uint8]                $out # unsigned char*
                                 ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/runtime.h ==

    #-From /usr/include/sodium/runtime.h:12
    #SODIUM_EXPORT
    #int sodium_runtime_has_neon(void);
    sub sodium_runtime_has_neon(
                                ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/runtime.h:15
    #SODIUM_EXPORT
    #int sodium_runtime_has_sse2(void);
    sub sodium_runtime_has_sse2(
                                ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/runtime.h:18
    #SODIUM_EXPORT
    #int sodium_runtime_has_sse3(void);
    sub sodium_runtime_has_sse3(
                                ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/runtime.h:21
    #SODIUM_EXPORT
    #int sodium_runtime_has_ssse3(void);
    sub sodium_runtime_has_ssse3(
                                 ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/runtime.h:24
    #SODIUM_EXPORT
    #int sodium_runtime_has_sse41(void);
    sub sodium_runtime_has_sse41(
                                 ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/runtime.h:27
    #SODIUM_EXPORT
    #int sodium_runtime_has_avx(void);
    sub sodium_runtime_has_avx(
                               ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/runtime.h:30
    #SODIUM_EXPORT
    #int sodium_runtime_has_pclmul(void);
    sub sodium_runtime_has_pclmul(
                                  ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/runtime.h:33
    #SODIUM_EXPORT
    #int sodium_runtime_has_aesni(void);
    sub sodium_runtime_has_aesni(
                                 ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/runtime.h:37
    #int _sodium_runtime_get_cpu_features(void);
    sub _sodium_runtime_get_cpu_features(
                                         ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_generichash.h ==

    #-From /usr/include/sodium/crypto_generichash.h:18
    ##define crypto_generichash_BYTES_MIN crypto_generichash_blake2b_BYTES_MIN
    #SODIUM_EXPORT
    #size_t  crypto_generichash_bytes_min(void);
    sub crypto_generichash_bytes_min(
                                     ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_generichash.h:22
    ##define crypto_generichash_BYTES_MAX crypto_generichash_blake2b_BYTES_MAX
    #SODIUM_EXPORT
    #size_t  crypto_generichash_bytes_max(void);
    sub crypto_generichash_bytes_max(
                                     ) is native(LIB) returns size_t { * }



    #-From /usr/include/sodium/crypto_generichash.h:30
    ##define crypto_generichash_KEYBYTES_MIN crypto_generichash_blake2b_KEYBYTES_MIN
    #SODIUM_EXPORT
    #size_t  crypto_generichash_keybytes_min(void);
    sub crypto_generichash_keybytes_min(
                                        ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_generichash.h:34
    ##define crypto_generichash_KEYBYTES_MAX crypto_generichash_blake2b_KEYBYTES_MAX
    #SODIUM_EXPORT
    #size_t  crypto_generichash_keybytes_max(void);
    sub crypto_generichash_keybytes_max(
                                        ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_generichash.h:38
    ##define crypto_generichash_KEYBYTES crypto_generichash_blake2b_KEYBYTES
    #SODIUM_EXPORT
    #size_t  crypto_generichash_keybytes(void);
    sub crypto_generichash_keybytes(
                                    ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_generichash.h:42
    ##define crypto_generichash_PRIMITIVE "blake2b"
    #SODIUM_EXPORT
    #const char *crypto_generichash_primitive(void);
    sub crypto_generichash_primitive(
                                     ) is native(LIB) returns Str { * }

    #-From /usr/include/sodium/crypto_generichash.h:46
    #SODIUM_EXPORT
    #size_t  crypto_generichash_statebytes(void);
    sub crypto_generichash_statebytes(
                                      ) is native(LIB) returns size_t { * }


    #-From /usr/include/sodium/crypto_generichash.h:54
    #SODIUM_EXPORT
    #int crypto_generichash_init(crypto_generichash_state *state,
    sub crypto_generichash_init(Pointer[crypto_generichash_blake2b_state]$state # Typedef<crypto_generichash_state>->|Typedef<crypto_generichash_blake2b_state>->|crypto_generichash_blake2b_state||*
                               ,Pointer[uint8]                $key # const unsigned char*
                               ,size_t                        $keylen # const Typedef<size_t>->|long unsigned int|
                               ,size_t                        $outlen # const Typedef<size_t>->|long unsigned int|
                                ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_generichash.h:59
    #SODIUM_EXPORT
    #int crypto_generichash_update(crypto_generichash_state *state,
    sub crypto_generichash_update(Pointer[crypto_generichash_blake2b_state]$state # Typedef<crypto_generichash_state>->|Typedef<crypto_generichash_blake2b_state>->|crypto_generichash_blake2b_state||*
                                 ,Pointer[uint8]                $in # const unsigned char*
                                 ,ulonglong                     $inlen # long long unsigned int
                                  ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_generichash.h:64
    #SODIUM_EXPORT
    #int crypto_generichash_final(crypto_generichash_state *state,
    sub crypto_generichash_final(Pointer[crypto_generichash_blake2b_state]$state # Typedef<crypto_generichash_state>->|Typedef<crypto_generichash_blake2b_state>->|crypto_generichash_blake2b_state||*
                                ,Pointer[uint8]                $out # unsigned char*
                                ,size_t                        $outlen # const Typedef<size_t>->|long unsigned int|
                                 ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_core_salsa208.h ==

    #-From /usr/include/sodium/crypto_core_salsa208.h:13
    ##define crypto_core_salsa208_OUTPUTBYTES 64U
    #SODIUM_EXPORT
    #size_t crypto_core_salsa208_outputbytes(void);
    sub crypto_core_salsa208_outputbytes(
                                         ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_core_salsa208.h:17
    ##define crypto_core_salsa208_INPUTBYTES 16U
    #SODIUM_EXPORT
    #size_t crypto_core_salsa208_inputbytes(void);
    sub crypto_core_salsa208_inputbytes(
                                        ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_core_salsa208.h:21
    ##define crypto_core_salsa208_KEYBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_core_salsa208_keybytes(void);
    sub crypto_core_salsa208_keybytes(
                                      ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_core_salsa208.h:25
    ##define crypto_core_salsa208_CONSTBYTES 16U
    #SODIUM_EXPORT
    #size_t crypto_core_salsa208_constbytes(void);
    sub crypto_core_salsa208_constbytes(
                                        ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_core_salsa208.h:28
    #SODIUM_EXPORT
    #int crypto_core_salsa208(unsigned char *out, const unsigned char *in,
    sub crypto_core_salsa208(Pointer[uint8]                $out # unsigned char*
                            ,Pointer[uint8]                $in # const unsigned char*
                            ,Pointer[uint8]                $k # const unsigned char*
                            ,Pointer[uint8]                $c # const unsigned char*
                             ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_box.h ==

    #-From /usr/include/sodium/crypto_box.h:25
    ##define crypto_box_SEEDBYTES crypto_box_curve25519xsalsa20poly1305_SEEDBYTES
    #SODIUM_EXPORT
    #size_t  crypto_box_seedbytes(void);
    sub crypto_box_seedbytes(
                             ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_box.h:29
    ##define crypto_box_PUBLICKEYBYTES crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES
    #SODIUM_EXPORT
    #size_t  crypto_box_publickeybytes(void);
    sub crypto_box_publickeybytes(
                                  ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_box.h:33
    ##define crypto_box_SECRETKEYBYTES crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES
    #SODIUM_EXPORT
    #size_t  crypto_box_secretkeybytes(void);
    sub crypto_box_secretkeybytes(
                                  ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_box.h:37
    ##define crypto_box_NONCEBYTES crypto_box_curve25519xsalsa20poly1305_NONCEBYTES
    #SODIUM_EXPORT
    #size_t  crypto_box_noncebytes(void);
    sub crypto_box_noncebytes(
                              ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_box.h:41
    ##define crypto_box_MACBYTES crypto_box_curve25519xsalsa20poly1305_MACBYTES
    #SODIUM_EXPORT
    #size_t  crypto_box_macbytes(void);
    sub crypto_box_macbytes(
                            ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_box.h:45
    ##define crypto_box_PRIMITIVE "curve25519xsalsa20poly1305"
    #SODIUM_EXPORT
    #const char *crypto_box_primitive(void);
    sub crypto_box_primitive(
                             ) is native(LIB) returns Str { * }

    #-From /usr/include/sodium/crypto_box.h:48
    #SODIUM_EXPORT
    #int crypto_box_seed_keypair(unsigned char *pk, unsigned char *sk,
    sub crypto_box_seed_keypair(Pointer[uint8]                $pk # unsigned char*
                               ,Pointer[uint8]                $sk # unsigned char*
                               ,Pointer[uint8]                $seed # const unsigned char*
                                ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_box.h:52
    #SODIUM_EXPORT
    #int crypto_box_keypair(unsigned char *pk, unsigned char *sk);
    sub crypto_box_keypair(Pointer[uint8]                $pk # unsigned char*
                          ,Pointer[uint8]                $sk # unsigned char*
                           ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_box.h:55
    #SODIUM_EXPORT
    #int crypto_box_easy(unsigned char *c, const unsigned char *m,
    sub crypto_box_easy(Pointer[uint8]                $c # unsigned char*
                       ,Pointer[uint8]                $m # const unsigned char*
                       ,ulonglong                     $mlen # long long unsigned int
                       ,Pointer[uint8]                $n # const unsigned char*
                       ,Pointer[uint8]                $pk # const unsigned char*
                       ,Pointer[uint8]                $sk # const unsigned char*
                        ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_box.h:61
    #SODIUM_EXPORT
    #int crypto_box_open_easy(unsigned char *m, const unsigned char *c,
    sub crypto_box_open_easy(Pointer[uint8]                $m # unsigned char*
                            ,Pointer[uint8]                $c # const unsigned char*
                            ,ulonglong                     $clen # long long unsigned int
                            ,Pointer[uint8]                $n # const unsigned char*
                            ,Pointer[uint8]                $pk # const unsigned char*
                            ,Pointer[uint8]                $sk # const unsigned char*
                             ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_box.h:67
    #SODIUM_EXPORT
    #int crypto_box_detached(unsigned char *c, unsigned char *mac,
    sub crypto_box_detached(Pointer[uint8]                $c # unsigned char*
                           ,Pointer[uint8]                $mac # unsigned char*
                           ,Pointer[uint8]                $m # const unsigned char*
                           ,ulonglong                     $mlen # long long unsigned int
                           ,Pointer[uint8]                $n # const unsigned char*
                           ,Pointer[uint8]                $pk # const unsigned char*
                           ,Pointer[uint8]                $sk # const unsigned char*
                            ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_box.h:74
    #SODIUM_EXPORT
    #int crypto_box_open_detached(unsigned char *m, const unsigned char *c,
    sub crypto_box_open_detached(Pointer[uint8]                $m # unsigned char*
                                ,Pointer[uint8]                $c # const unsigned char*
                                ,Pointer[uint8]                $mac # const unsigned char*
                                ,ulonglong                     $clen # long long unsigned int
                                ,Pointer[uint8]                $n # const unsigned char*
                                ,Pointer[uint8]                $pk # const unsigned char*
                                ,Pointer[uint8]                $sk # const unsigned char*
                                 ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_box.h:86
    ##define crypto_box_BEFORENMBYTES crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES
    #SODIUM_EXPORT
    #size_t  crypto_box_beforenmbytes(void);
    sub crypto_box_beforenmbytes(
                                 ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_box.h:89
    #SODIUM_EXPORT
    #int crypto_box_beforenm(unsigned char *k, const unsigned char *pk,
    sub crypto_box_beforenm(Pointer[uint8]                $k # unsigned char*
                           ,Pointer[uint8]                $pk # const unsigned char*
                           ,Pointer[uint8]                $sk # const unsigned char*
                            ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_box.h:94
    #SODIUM_EXPORT
    #int crypto_box_easy_afternm(unsigned char *c, const unsigned char *m,
    sub crypto_box_easy_afternm(Pointer[uint8]                $c # unsigned char*
                               ,Pointer[uint8]                $m # const unsigned char*
                               ,ulonglong                     $mlen # long long unsigned int
                               ,Pointer[uint8]                $n # const unsigned char*
                               ,Pointer[uint8]                $k # const unsigned char*
                                ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_box.h:99
    #SODIUM_EXPORT
    #int crypto_box_open_easy_afternm(unsigned char *m, const unsigned char *c,
    sub crypto_box_open_easy_afternm(Pointer[uint8]                $m # unsigned char*
                                    ,Pointer[uint8]                $c # const unsigned char*
                                    ,ulonglong                     $clen # long long unsigned int
                                    ,Pointer[uint8]                $n # const unsigned char*
                                    ,Pointer[uint8]                $k # const unsigned char*
                                     ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_box.h:105
    #SODIUM_EXPORT
    #int crypto_box_detached_afternm(unsigned char *c, unsigned char *mac,
    sub crypto_box_detached_afternm(Pointer[uint8]                $c # unsigned char*
                                   ,Pointer[uint8]                $mac # unsigned char*
                                   ,Pointer[uint8]                $m # const unsigned char*
                                   ,ulonglong                     $mlen # long long unsigned int
                                   ,Pointer[uint8]                $n # const unsigned char*
                                   ,Pointer[uint8]                $k # const unsigned char*
                                    ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_box.h:110
    #SODIUM_EXPORT
    #int crypto_box_open_detached_afternm(unsigned char *m, const unsigned char *c,
    sub crypto_box_open_detached_afternm(Pointer[uint8]                $m # unsigned char*
                                        ,Pointer[uint8]                $c # const unsigned char*
                                        ,Pointer[uint8]                $mac # const unsigned char*
                                        ,ulonglong                     $clen # long long unsigned int
                                        ,Pointer[uint8]                $n # const unsigned char*
                                        ,Pointer[uint8]                $k # const unsigned char*
                                         ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_box.h:120
    ##define crypto_box_SEALBYTES (crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES)
    #SODIUM_EXPORT
    #size_t crypto_box_sealbytes(void);
    sub crypto_box_sealbytes(
                             ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_box.h:123
    #SODIUM_EXPORT
    #int crypto_box_seal(unsigned char *c, const unsigned char *m,
    sub crypto_box_seal(Pointer[uint8]                $c # unsigned char*
                       ,Pointer[uint8]                $m # const unsigned char*
                       ,ulonglong                     $mlen # long long unsigned int
                       ,Pointer[uint8]                $pk # const unsigned char*
                        ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_box.h:127
    #SODIUM_EXPORT
    #int crypto_box_seal_open(unsigned char *m, const unsigned char *c,
    sub crypto_box_seal_open(Pointer[uint8]                $m # unsigned char*
                            ,Pointer[uint8]                $c # const unsigned char*
                            ,ulonglong                     $clen # long long unsigned int
                            ,Pointer[uint8]                $pk # const unsigned char*
                            ,Pointer[uint8]                $sk # const unsigned char*
                             ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_box.h:136
    ##define crypto_box_ZEROBYTES crypto_box_curve25519xsalsa20poly1305_ZEROBYTES
    #SODIUM_EXPORT
    #size_t  crypto_box_zerobytes(void);
    sub crypto_box_zerobytes(
                             ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_box.h:140
    ##define crypto_box_BOXZEROBYTES crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES
    #SODIUM_EXPORT
    #size_t  crypto_box_boxzerobytes(void);
    sub crypto_box_boxzerobytes(
                                ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_box.h:143
    #SODIUM_EXPORT
    #int crypto_box(unsigned char *c, const unsigned char *m,
    sub crypto_box(Pointer[uint8]                $c # unsigned char*
                  ,Pointer[uint8]                $m # const unsigned char*
                  ,ulonglong                     $mlen # long long unsigned int
                  ,Pointer[uint8]                $n # const unsigned char*
                  ,Pointer[uint8]                $pk # const unsigned char*
                  ,Pointer[uint8]                $sk # const unsigned char*
                   ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_box.h:149
    #SODIUM_EXPORT
    #int crypto_box_open(unsigned char *m, const unsigned char *c,
    sub crypto_box_open(Pointer[uint8]                $m # unsigned char*
                       ,Pointer[uint8]                $c # const unsigned char*
                       ,ulonglong                     $clen # long long unsigned int
                       ,Pointer[uint8]                $n # const unsigned char*
                       ,Pointer[uint8]                $pk # const unsigned char*
                       ,Pointer[uint8]                $sk # const unsigned char*
                        ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_box.h:155
    #SODIUM_EXPORT
    #int crypto_box_afternm(unsigned char *c, const unsigned char *m,
    sub crypto_box_afternm(Pointer[uint8]                $c # unsigned char*
                          ,Pointer[uint8]                $m # const unsigned char*
                          ,ulonglong                     $mlen # long long unsigned int
                          ,Pointer[uint8]                $n # const unsigned char*
                          ,Pointer[uint8]                $k # const unsigned char*
                           ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_box.h:160
    #SODIUM_EXPORT
    #int crypto_box_open_afternm(unsigned char *m, const unsigned char *c,
    sub crypto_box_open_afternm(Pointer[uint8]                $m # unsigned char*
                               ,Pointer[uint8]                $c # const unsigned char*
                               ,ulonglong                     $clen # long long unsigned int
                               ,Pointer[uint8]                $n # const unsigned char*
                               ,Pointer[uint8]                $k # const unsigned char*
                                ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_shorthash_siphash24.h ==

    #-From /usr/include/sodium/crypto_shorthash_siphash24.h:16
    ##define crypto_shorthash_siphash24_BYTES 8U
    #SODIUM_EXPORT
    #size_t crypto_shorthash_siphash24_bytes(void);
    sub crypto_shorthash_siphash24_bytes(
                                         ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_shorthash_siphash24.h:20
    ##define crypto_shorthash_siphash24_KEYBYTES 16U
    #SODIUM_EXPORT
    #size_t crypto_shorthash_siphash24_keybytes(void);
    sub crypto_shorthash_siphash24_keybytes(
                                            ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_shorthash_siphash24.h:23
    #SODIUM_EXPORT
    #int crypto_shorthash_siphash24(unsigned char *out, const unsigned char *in,
    sub crypto_shorthash_siphash24(Pointer[uint8]                $out # unsigned char*
                                  ,Pointer[uint8]                $in # const unsigned char*
                                  ,ulonglong                     $inlen # long long unsigned int
                                  ,Pointer[uint8]                $k # const unsigned char*
                                   ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_verify_64.h ==

    #-From /usr/include/sodium/crypto_verify_64.h:13
    ##define crypto_verify_64_BYTES 64U
    #SODIUM_EXPORT
    #size_t crypto_verify_64_bytes(void);
    sub crypto_verify_64_bytes(
                               ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_verify_64.h:16
    #SODIUM_EXPORT
    #int crypto_verify_64(const unsigned char *x, const unsigned char *y)
    sub crypto_verify_64(Pointer[uint8]                $x # const unsigned char*
                        ,Pointer[uint8]                $y # const unsigned char*
                         ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_auth_hmacsha256.h ==

    #-From /usr/include/sodium/crypto_auth_hmacsha256.h:17
    ##define crypto_auth_hmacsha256_BYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_auth_hmacsha256_bytes(void);
    sub crypto_auth_hmacsha256_bytes(
                                     ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_auth_hmacsha256.h:21
    ##define crypto_auth_hmacsha256_KEYBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_auth_hmacsha256_keybytes(void);
    sub crypto_auth_hmacsha256_keybytes(
                                        ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_auth_hmacsha256.h:24
    #SODIUM_EXPORT
    #int crypto_auth_hmacsha256(unsigned char *out,
    sub crypto_auth_hmacsha256(Pointer[uint8]                $out # unsigned char*
                              ,Pointer[uint8]                $in # const unsigned char*
                              ,ulonglong                     $inlen # long long unsigned int
                              ,Pointer[uint8]                $k # const unsigned char*
                               ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_auth_hmacsha256.h:30
    #SODIUM_EXPORT
    #int crypto_auth_hmacsha256_verify(const unsigned char *h,
    sub crypto_auth_hmacsha256_verify(Pointer[uint8]                $h # const unsigned char*
                                     ,Pointer[uint8]                $in # const unsigned char*
                                     ,ulonglong                     $inlen # long long unsigned int
                                     ,Pointer[uint8]                $k # const unsigned char*
                                      ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_auth_hmacsha256.h:43
    #SODIUM_EXPORT
    #size_t crypto_auth_hmacsha256_statebytes(void);
    sub crypto_auth_hmacsha256_statebytes(
                                          ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_auth_hmacsha256.h:46
    #SODIUM_EXPORT
    #int crypto_auth_hmacsha256_init(crypto_auth_hmacsha256_state *state,
    sub crypto_auth_hmacsha256_init(crypto_auth_hmacsha256_state  $state # Typedef<crypto_auth_hmacsha256_state>->|crypto_auth_hmacsha256_state|*
                                   ,Pointer[uint8]                $key # const unsigned char*
                                   ,size_t                        $keylen # Typedef<size_t>->|long unsigned int|
                                    ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_auth_hmacsha256.h:51
    #SODIUM_EXPORT
    #int crypto_auth_hmacsha256_update(crypto_auth_hmacsha256_state *state,
    sub crypto_auth_hmacsha256_update(crypto_auth_hmacsha256_state  $state # Typedef<crypto_auth_hmacsha256_state>->|crypto_auth_hmacsha256_state|*
                                     ,Pointer[uint8]                $in # const unsigned char*
                                     ,ulonglong                     $inlen # long long unsigned int
                                      ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_auth_hmacsha256.h:56
    #SODIUM_EXPORT
    #int crypto_auth_hmacsha256_final(crypto_auth_hmacsha256_state *state,
    sub crypto_auth_hmacsha256_final(crypto_auth_hmacsha256_state  $state # Typedef<crypto_auth_hmacsha256_state>->|crypto_auth_hmacsha256_state|*
                                    ,Pointer[uint8]                $out # unsigned char*
                                     ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_stream_chacha20.h ==

    #-From /usr/include/sodium/crypto_stream_chacha20.h:25
    ##define crypto_stream_chacha20_KEYBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_stream_chacha20_keybytes(void);
    sub crypto_stream_chacha20_keybytes(
                                        ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_stream_chacha20.h:29
    ##define crypto_stream_chacha20_NONCEBYTES 8U
    #SODIUM_EXPORT
    #size_t crypto_stream_chacha20_noncebytes(void);
    sub crypto_stream_chacha20_noncebytes(
                                          ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_stream_chacha20.h:34
    #SODIUM_EXPORT
    #int crypto_stream_chacha20(unsigned char *c, unsigned long long clen,
    sub crypto_stream_chacha20(Pointer[uint8]                $c # unsigned char*
                              ,ulonglong                     $clen # long long unsigned int
                              ,Pointer[uint8]                $n # const unsigned char*
                              ,Pointer[uint8]                $k # const unsigned char*
                               ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_stream_chacha20.h:38
    #SODIUM_EXPORT
    #int crypto_stream_chacha20_xor(unsigned char *c, const unsigned char *m,
    sub crypto_stream_chacha20_xor(Pointer[uint8]                $c # unsigned char*
                                  ,Pointer[uint8]                $m # const unsigned char*
                                  ,ulonglong                     $mlen # long long unsigned int
                                  ,Pointer[uint8]                $n # const unsigned char*
                                  ,Pointer[uint8]                $k # const unsigned char*
                                   ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_stream_chacha20.h:43
    #SODIUM_EXPORT
    #int crypto_stream_chacha20_xor_ic(unsigned char *c, const unsigned char *m,
    sub crypto_stream_chacha20_xor_ic(Pointer[uint8]                $c # unsigned char*
                                     ,Pointer[uint8]                $m # const unsigned char*
                                     ,ulonglong                     $mlen # long long unsigned int
                                     ,Pointer[uint8]                $n # const unsigned char*
                                     ,uint64                      $ic # Typedef<uint64>->|long unsigned int|
                                     ,Pointer[uint8]                $k # const unsigned char*
                                      ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_stream_chacha20.h:52
    ##define crypto_stream_chacha20_IETF_NONCEBYTES 12U
    #SODIUM_EXPORT
    #size_t crypto_stream_chacha20_ietf_noncebytes(void);
    sub crypto_stream_chacha20_ietf_noncebytes(
                                               ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_stream_chacha20.h:55
    #SODIUM_EXPORT
    #int crypto_stream_chacha20_ietf(unsigned char *c, unsigned long long clen,
    sub crypto_stream_chacha20_ietf(Pointer[uint8]                $c # unsigned char*
                                   ,ulonglong                     $clen # long long unsigned int
                                   ,Pointer[uint8]                $n # const unsigned char*
                                   ,Pointer[uint8]                $k # const unsigned char*
                                    ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_stream_chacha20.h:59
    #SODIUM_EXPORT
    #int crypto_stream_chacha20_ietf_xor(unsigned char *c, const unsigned char *m,
    sub crypto_stream_chacha20_ietf_xor(Pointer[uint8]                $c # unsigned char*
                                       ,Pointer[uint8]                $m # const unsigned char*
                                       ,ulonglong                     $mlen # long long unsigned int
                                       ,Pointer[uint8]                $n # const unsigned char*
                                       ,Pointer[uint8]                $k # const unsigned char*
                                        ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_stream_chacha20.h:64
    #SODIUM_EXPORT
    #int crypto_stream_chacha20_ietf_xor_ic(unsigned char *c, const unsigned char *m,
    sub crypto_stream_chacha20_ietf_xor_ic(Pointer[uint8]                $c # unsigned char*
                                          ,Pointer[uint8]                $m # const unsigned char*
                                          ,ulonglong                     $mlen # long long unsigned int
                                          ,Pointer[uint8]                $n # const unsigned char*
                                          ,uint32                      $ic # Typedef<uint32>->|unsigned int|
                                          ,Pointer[uint8]                $k # const unsigned char*
                                           ) is native(LIB) returns int32 { * }

    #-From /usr/include/sodium/crypto_stream_chacha20.h:71
    #int _crypto_stream_chacha20_pick_best_implementation(void);
    sub _crypto_stream_chacha20_pick_best_implementation(
                                                         ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_core_salsa20.h ==

    #-From /usr/include/sodium/crypto_core_salsa20.h:13
    ##define crypto_core_salsa20_OUTPUTBYTES 64U
    #SODIUM_EXPORT
    #size_t crypto_core_salsa20_outputbytes(void);
    sub crypto_core_salsa20_outputbytes(
                                        ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_core_salsa20.h:17
    ##define crypto_core_salsa20_INPUTBYTES 16U
    #SODIUM_EXPORT
    #size_t crypto_core_salsa20_inputbytes(void);
    sub crypto_core_salsa20_inputbytes(
                                       ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_core_salsa20.h:21
    ##define crypto_core_salsa20_KEYBYTES 32U
    #SODIUM_EXPORT
    #size_t crypto_core_salsa20_keybytes(void);
    sub crypto_core_salsa20_keybytes(
                                     ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_core_salsa20.h:25
    ##define crypto_core_salsa20_CONSTBYTES 16U
    #SODIUM_EXPORT
    #size_t crypto_core_salsa20_constbytes(void);
    sub crypto_core_salsa20_constbytes(
                                       ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_core_salsa20.h:28
    #SODIUM_EXPORT
    #int crypto_core_salsa20(unsigned char *out, const unsigned char *in,
    sub crypto_core_salsa20(Pointer[uint8]                $out # unsigned char*
                           ,Pointer[uint8]                $in # const unsigned char*
                           ,Pointer[uint8]                $k # const unsigned char*
                           ,Pointer[uint8]                $c # const unsigned char*
                            ) is native(LIB) returns int32 { * }


    # == /usr/include/sodium/crypto_verify_16.h ==

    #-From /usr/include/sodium/crypto_verify_16.h:13
    ##define crypto_verify_16_BYTES 16U
    #SODIUM_EXPORT
    #size_t crypto_verify_16_bytes(void);
    sub crypto_verify_16_bytes(
                               ) is native(LIB) returns size_t { * }

    #-From /usr/include/sodium/crypto_verify_16.h:16
    #SODIUM_EXPORT
    #int crypto_verify_16(const unsigned char *x, const unsigned char *y)
    sub crypto_verify_16(Pointer[uint8]                $x # const unsigned char*
                        ,Pointer[uint8]                $y # const unsigned char*
                         ) is native(LIB) returns int32 { * }


}

# vim: ft=perl6
