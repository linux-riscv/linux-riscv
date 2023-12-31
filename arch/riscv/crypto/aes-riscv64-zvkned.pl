#! /usr/bin/env perl
# SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause
#
# This file is dual-licensed, meaning that you can use it under your
# choice of either of the following two licenses:
#
# Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License"). You can obtain
# a copy in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# or
#
# Copyright (c) 2023, Christoph Müllner <christoph.muellner@vrull.eu>
# Copyright (c) 2023, Phoebe Chen <phoebe.chen@sifive.com>
# Copyright (c) 2023, Jerry Shih <jerry.shih@sifive.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# - RV64I
# - RISC-V Vector ('V') with VLEN >= 128
# - RISC-V Vector AES block cipher extension ('Zvkned')

use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin";
use lib "$Bin/../../perlasm";

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
my $output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
my $flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$output and open STDOUT,">$output";

my $code=<<___;
.text
.option arch, +zvkned
___

my ($V0, $V1, $V2, $V3, $V4, $V5, $V6, $V7,
    $V8, $V9, $V10, $V11, $V12, $V13, $V14, $V15,
    $V16, $V17, $V18, $V19, $V20, $V21, $V22, $V23,
    $V24, $V25, $V26, $V27, $V28, $V29, $V30, $V31,
) = map("v$_",(0..31));

# Load all 11 round keys to v1-v11 registers.
sub aes_128_load_key {
    my $KEYP = shift;

    my $code=<<___;
    vsetivli zero, 4, e32, m1, ta, ma
    vle32.v $V1, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V2, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V3, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V4, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V5, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V6, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V7, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V8, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V9, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V10, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V11, ($KEYP)
___

    return $code;
}

# Load all 13 round keys to v1-v13 registers.
sub aes_192_load_key {
    my $KEYP = shift;

    my $code=<<___;
    vsetivli zero, 4, e32, m1, ta, ma
    vle32.v $V1, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V2, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V3, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V4, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V5, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V6, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V7, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V8, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V9, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V10, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V11, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V12, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V13, ($KEYP)
___

    return $code;
}

# Load all 15 round keys to v1-v15 registers.
sub aes_256_load_key {
    my $KEYP = shift;

    my $code=<<___;
    vsetivli zero, 4, e32, m1, ta, ma
    vle32.v $V1, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V2, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V3, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V4, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V5, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V6, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V7, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V8, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V9, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V10, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V11, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V12, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V13, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V14, ($KEYP)
    addi $KEYP, $KEYP, 16
    vle32.v $V15, ($KEYP)
___

    return $code;
}

# aes-128 encryption with round keys v1-v11
sub aes_128_encrypt {
    my $code=<<___;
    vaesz.vs $V24, $V1     # with round key w[ 0, 3]
    vaesem.vs $V24, $V2    # with round key w[ 4, 7]
    vaesem.vs $V24, $V3    # with round key w[ 8,11]
    vaesem.vs $V24, $V4    # with round key w[12,15]
    vaesem.vs $V24, $V5    # with round key w[16,19]
    vaesem.vs $V24, $V6    # with round key w[20,23]
    vaesem.vs $V24, $V7    # with round key w[24,27]
    vaesem.vs $V24, $V8    # with round key w[28,31]
    vaesem.vs $V24, $V9    # with round key w[32,35]
    vaesem.vs $V24, $V10   # with round key w[36,39]
    vaesef.vs $V24, $V11   # with round key w[40,43]
___

    return $code;
}

# aes-128 decryption with round keys v1-v11
sub aes_128_decrypt {
    my $code=<<___;
    vaesz.vs $V24, $V11   # with round key w[40,43]
    vaesdm.vs $V24, $V10  # with round key w[36,39]
    vaesdm.vs $V24, $V9   # with round key w[32,35]
    vaesdm.vs $V24, $V8   # with round key w[28,31]
    vaesdm.vs $V24, $V7   # with round key w[24,27]
    vaesdm.vs $V24, $V6   # with round key w[20,23]
    vaesdm.vs $V24, $V5   # with round key w[16,19]
    vaesdm.vs $V24, $V4   # with round key w[12,15]
    vaesdm.vs $V24, $V3   # with round key w[ 8,11]
    vaesdm.vs $V24, $V2   # with round key w[ 4, 7]
    vaesdf.vs $V24, $V1   # with round key w[ 0, 3]
___

    return $code;
}

# aes-192 encryption with round keys v1-v13
sub aes_192_encrypt {
    my $code=<<___;
    vaesz.vs $V24, $V1     # with round key w[ 0, 3]
    vaesem.vs $V24, $V2    # with round key w[ 4, 7]
    vaesem.vs $V24, $V3    # with round key w[ 8,11]
    vaesem.vs $V24, $V4    # with round key w[12,15]
    vaesem.vs $V24, $V5    # with round key w[16,19]
    vaesem.vs $V24, $V6    # with round key w[20,23]
    vaesem.vs $V24, $V7    # with round key w[24,27]
    vaesem.vs $V24, $V8    # with round key w[28,31]
    vaesem.vs $V24, $V9    # with round key w[32,35]
    vaesem.vs $V24, $V10   # with round key w[36,39]
    vaesem.vs $V24, $V11   # with round key w[40,43]
    vaesem.vs $V24, $V12   # with round key w[44,47]
    vaesef.vs $V24, $V13   # with round key w[48,51]
___

    return $code;
}

# aes-192 decryption with round keys v1-v13
sub aes_192_decrypt {
    my $code=<<___;
    vaesz.vs $V24, $V13    # with round key w[48,51]
    vaesdm.vs $V24, $V12   # with round key w[44,47]
    vaesdm.vs $V24, $V11   # with round key w[40,43]
    vaesdm.vs $V24, $V10   # with round key w[36,39]
    vaesdm.vs $V24, $V9    # with round key w[32,35]
    vaesdm.vs $V24, $V8    # with round key w[28,31]
    vaesdm.vs $V24, $V7    # with round key w[24,27]
    vaesdm.vs $V24, $V6    # with round key w[20,23]
    vaesdm.vs $V24, $V5    # with round key w[16,19]
    vaesdm.vs $V24, $V4    # with round key w[12,15]
    vaesdm.vs $V24, $V3    # with round key w[ 8,11]
    vaesdm.vs $V24, $V2    # with round key w[ 4, 7]
    vaesdf.vs $V24, $V1    # with round key w[ 0, 3]
___

    return $code;
}

# aes-256 encryption with round keys v1-v15
sub aes_256_encrypt {
    my $code=<<___;
    vaesz.vs $V24, $V1     # with round key w[ 0, 3]
    vaesem.vs $V24, $V2    # with round key w[ 4, 7]
    vaesem.vs $V24, $V3    # with round key w[ 8,11]
    vaesem.vs $V24, $V4    # with round key w[12,15]
    vaesem.vs $V24, $V5    # with round key w[16,19]
    vaesem.vs $V24, $V6    # with round key w[20,23]
    vaesem.vs $V24, $V7    # with round key w[24,27]
    vaesem.vs $V24, $V8    # with round key w[28,31]
    vaesem.vs $V24, $V9    # with round key w[32,35]
    vaesem.vs $V24, $V10   # with round key w[36,39]
    vaesem.vs $V24, $V11   # with round key w[40,43]
    vaesem.vs $V24, $V12   # with round key w[44,47]
    vaesem.vs $V24, $V13   # with round key w[48,51]
    vaesem.vs $V24, $V14   # with round key w[52,55]
    vaesef.vs $V24, $V15   # with round key w[56,59]
___

    return $code;
}

# aes-256 decryption with round keys v1-v15
sub aes_256_decrypt {
    my $code=<<___;
    vaesz.vs $V24, $V15    # with round key w[56,59]
    vaesdm.vs $V24, $V14   # with round key w[52,55]
    vaesdm.vs $V24, $V13   # with round key w[48,51]
    vaesdm.vs $V24, $V12   # with round key w[44,47]
    vaesdm.vs $V24, $V11   # with round key w[40,43]
    vaesdm.vs $V24, $V10   # with round key w[36,39]
    vaesdm.vs $V24, $V9    # with round key w[32,35]
    vaesdm.vs $V24, $V8    # with round key w[28,31]
    vaesdm.vs $V24, $V7    # with round key w[24,27]
    vaesdm.vs $V24, $V6    # with round key w[20,23]
    vaesdm.vs $V24, $V5    # with round key w[16,19]
    vaesdm.vs $V24, $V4    # with round key w[12,15]
    vaesdm.vs $V24, $V3    # with round key w[ 8,11]
    vaesdm.vs $V24, $V2    # with round key w[ 4, 7]
    vaesdf.vs $V24, $V1    # with round key w[ 0, 3]
___

    return $code;
}

{
###############################################################################
# void rv64i_zvkned_cbc_encrypt(const unsigned char *in, unsigned char *out,
#                               size_t length, const AES_KEY *key,
#                               unsigned char *ivec, const int enc);
my ($INP, $OUTP, $LEN, $KEYP, $IVP, $ENC) = ("a0", "a1", "a2", "a3", "a4", "a5");
my ($T0, $T1) = ("t0", "t1", "t2");

$code .= <<___;
.p2align 3
.globl rv64i_zvkned_cbc_encrypt
.type rv64i_zvkned_cbc_encrypt,\@function
rv64i_zvkned_cbc_encrypt:
    # check whether the length is a multiple of 16 and >= 16
    li $T1, 16
    blt $LEN, $T1, L_end
    andi $T1, $LEN, 15
    bnez $T1, L_end

    # Load key length.
    lwu $T0, 480($KEYP)

    # Get proper routine for key length.
    li $T1, 16
    beq $T1, $T0, L_cbc_enc_128

    li $T1, 24
    beq $T1, $T0, L_cbc_enc_192

    li $T1, 32
    beq $T1, $T0, L_cbc_enc_256

    ret
.size rv64i_zvkned_cbc_encrypt,.-rv64i_zvkned_cbc_encrypt
___

$code .= <<___;
.p2align 3
L_cbc_enc_128:
    # Load all 11 round keys to v1-v11 registers.
    @{[aes_128_load_key $KEYP]}

    # Load IV.
    vle32.v $V16, ($IVP)

    vle32.v $V24, ($INP)
    vxor.vv $V24, $V24, $V16
    j 2f

1:
    vle32.v $V17, ($INP)
    vxor.vv $V24, $V24, $V17

2:
    # AES body
    @{[aes_128_encrypt]}

    vse32.v $V24, ($OUTP)

    addi $INP, $INP, 16
    addi $OUTP, $OUTP, 16
    addi $LEN, $LEN, -16

    bnez $LEN, 1b

    vse32.v $V24, ($IVP)

    ret
.size L_cbc_enc_128,.-L_cbc_enc_128
___

$code .= <<___;
.p2align 3
L_cbc_enc_192:
    # Load all 13 round keys to v1-v13 registers.
    @{[aes_192_load_key $KEYP]}

    # Load IV.
    vle32.v $V16, ($IVP)

    vle32.v $V24, ($INP)
    vxor.vv $V24, $V24, $V16
    j 2f

1:
    vle32.v $V17, ($INP)
    vxor.vv $V24, $V24, $V17

2:
    # AES body
    @{[aes_192_encrypt]}

    vse32.v $V24, ($OUTP)

    addi $INP, $INP, 16
    addi $OUTP, $OUTP, 16
    addi $LEN, $LEN, -16

    bnez $LEN, 1b

    vse32.v $V24, ($IVP)

    ret
.size L_cbc_enc_192,.-L_cbc_enc_192
___

$code .= <<___;
.p2align 3
L_cbc_enc_256:
    # Load all 15 round keys to v1-v15 registers.
    @{[aes_256_load_key $KEYP]}

    # Load IV.
    vle32.v $V16, ($IVP)

    vle32.v $V24, ($INP)
    vxor.vv $V24, $V24, $V16
    j 2f

1:
    vle32.v $V17, ($INP)
    vxor.vv $V24, $V24, $V17

2:
    # AES body
    @{[aes_256_encrypt]}

    vse32.v $V24, ($OUTP)

    addi $INP, $INP, 16
    addi $OUTP, $OUTP, 16
    addi $LEN, $LEN, -16

    bnez $LEN, 1b

    vse32.v $V24, ($IVP)

    ret
.size L_cbc_enc_256,.-L_cbc_enc_256
___

###############################################################################
# void rv64i_zvkned_cbc_decrypt(const unsigned char *in, unsigned char *out,
#                               size_t length, const AES_KEY *key,
#                               unsigned char *ivec, const int enc);
$code .= <<___;
.p2align 3
.globl rv64i_zvkned_cbc_decrypt
.type rv64i_zvkned_cbc_decrypt,\@function
rv64i_zvkned_cbc_decrypt:
    # check whether the length is a multiple of 16 and >= 16
    li $T1, 16
    blt $LEN, $T1, L_end
    andi $T1, $LEN, 15
    bnez $T1, L_end

    # Load key length.
    lwu $T0, 480($KEYP)

    # Get proper routine for key length.
    li $T1, 16
    beq $T1, $T0, L_cbc_dec_128

    li $T1, 24
    beq $T1, $T0, L_cbc_dec_192

    li $T1, 32
    beq $T1, $T0, L_cbc_dec_256

    ret
.size rv64i_zvkned_cbc_decrypt,.-rv64i_zvkned_cbc_decrypt
___

$code .= <<___;
.p2align 3
L_cbc_dec_128:
    # Load all 11 round keys to v1-v11 registers.
    @{[aes_128_load_key $KEYP]}

    # Load IV.
    vle32.v $V16, ($IVP)

    vle32.v $V24, ($INP)
    vmv.v.v $V17, $V24
    j 2f

1:
    vle32.v $V24, ($INP)
    vmv.v.v $V17, $V24
    addi $OUTP, $OUTP, 16

2:
    # AES body
    @{[aes_128_decrypt]}

    vxor.vv $V24, $V24, $V16
    vse32.v $V24, ($OUTP)
    vmv.v.v $V16, $V17

    addi $LEN, $LEN, -16
    addi $INP, $INP, 16

    bnez $LEN, 1b

    vse32.v $V16, ($IVP)

    ret
.size L_cbc_dec_128,.-L_cbc_dec_128
___

$code .= <<___;
.p2align 3
L_cbc_dec_192:
    # Load all 13 round keys to v1-v13 registers.
    @{[aes_192_load_key $KEYP]}

    # Load IV.
    vle32.v $V16, ($IVP)

    vle32.v $V24, ($INP)
    vmv.v.v $V17, $V24
    j 2f

1:
    vle32.v $V24, ($INP)
    vmv.v.v $V17, $V24
    addi $OUTP, $OUTP, 16

2:
    # AES body
    @{[aes_192_decrypt]}

    vxor.vv $V24, $V24, $V16
    vse32.v $V24, ($OUTP)
    vmv.v.v $V16, $V17

    addi $LEN, $LEN, -16
    addi $INP, $INP, 16

    bnez $LEN, 1b

    vse32.v $V16, ($IVP)

    ret
.size L_cbc_dec_192,.-L_cbc_dec_192
___

$code .= <<___;
.p2align 3
L_cbc_dec_256:
    # Load all 15 round keys to v1-v15 registers.
    @{[aes_256_load_key $KEYP]}

    # Load IV.
    vle32.v $V16, ($IVP)

    vle32.v $V24, ($INP)
    vmv.v.v $V17, $V24
    j 2f

1:
    vle32.v $V24, ($INP)
    vmv.v.v $V17, $V24
    addi $OUTP, $OUTP, 16

2:
    # AES body
    @{[aes_256_decrypt]}

    vxor.vv $V24, $V24, $V16
    vse32.v $V24, ($OUTP)
    vmv.v.v $V16, $V17

    addi $LEN, $LEN, -16
    addi $INP, $INP, 16

    bnez $LEN, 1b

    vse32.v $V16, ($IVP)

    ret
.size L_cbc_dec_256,.-L_cbc_dec_256
___
}

{
###############################################################################
# void rv64i_zvkned_ecb_encrypt(const unsigned char *in, unsigned char *out,
#                               size_t length, const AES_KEY *key,
#                               const int enc);
my ($INP, $OUTP, $LEN, $KEYP, $ENC) = ("a0", "a1", "a2", "a3", "a4");
my ($VL) = ("a5");
my ($LEN32) = ("a6");
my ($T0, $T1) = ("t0", "t1");

$code .= <<___;
.p2align 3
.globl rv64i_zvkned_ecb_encrypt
.type rv64i_zvkned_ecb_encrypt,\@function
rv64i_zvkned_ecb_encrypt:
    # Make the LEN become e32 length.
    srli $LEN32, $LEN, 2

    # Load key length.
    lwu $T0, 480($KEYP)

    # Get proper routine for key length.
    li $T1, 16
    beq $T1, $T0, L_ecb_enc_128

    li $T1, 24
    beq $T1, $T0, L_ecb_enc_192

    li $T1, 32
    beq $T1, $T0, L_ecb_enc_256

    ret
.size rv64i_zvkned_ecb_encrypt,.-rv64i_zvkned_ecb_encrypt
___

$code .= <<___;
.p2align 3
L_ecb_enc_128:
    # Load all 11 round keys to v1-v11 registers.
    @{[aes_128_load_key $KEYP]}

1:
    vsetvli $VL, $LEN32, e32, m4, ta, ma
    slli $T0, $VL, 2
    sub $LEN32, $LEN32, $VL

    vle32.v $V24, ($INP)

    # AES body
    @{[aes_128_encrypt]}

    vse32.v $V24, ($OUTP)

    add $INP, $INP, $T0
    add $OUTP, $OUTP, $T0

    bnez $LEN32, 1b

    ret
.size L_ecb_enc_128,.-L_ecb_enc_128
___

$code .= <<___;
.p2align 3
L_ecb_enc_192:
    # Load all 13 round keys to v1-v13 registers.
    @{[aes_192_load_key $KEYP]}

1:
    vsetvli $VL, $LEN32, e32, m4, ta, ma
    slli $T0, $VL, 2
    sub $LEN32, $LEN32, $VL

    vle32.v $V24, ($INP)

    # AES body
    @{[aes_192_encrypt]}

    vse32.v $V24, ($OUTP)

    add $INP, $INP, $T0
    add $OUTP, $OUTP, $T0

    bnez $LEN32, 1b

    ret
.size L_ecb_enc_192,.-L_ecb_enc_192
___

$code .= <<___;
.p2align 3
L_ecb_enc_256:
    # Load all 15 round keys to v1-v15 registers.
    @{[aes_256_load_key $KEYP]}

1:
    vsetvli $VL, $LEN32, e32, m4, ta, ma
    slli $T0, $VL, 2
    sub $LEN32, $LEN32, $VL

    vle32.v $V24, ($INP)

    # AES body
    @{[aes_256_encrypt]}

    vse32.v $V24, ($OUTP)

    add $INP, $INP, $T0
    add $OUTP, $OUTP, $T0

    bnez $LEN32, 1b

    ret
.size L_ecb_enc_256,.-L_ecb_enc_256
___

###############################################################################
# void rv64i_zvkned_ecb_decrypt(const unsigned char *in, unsigned char *out,
#                               size_t length, const AES_KEY *key,
#                               const int enc);
$code .= <<___;
.p2align 3
.globl rv64i_zvkned_ecb_decrypt
.type rv64i_zvkned_ecb_decrypt,\@function
rv64i_zvkned_ecb_decrypt:
    # Make the LEN become e32 length.
    srli $LEN32, $LEN, 2

    # Load key length.
    lwu $T0, 480($KEYP)

    # Get proper routine for key length.
    li $T1, 16
    beq $T1, $T0, L_ecb_dec_128

    li $T1, 24
    beq $T1, $T0, L_ecb_dec_192

    li $T1, 32
    beq $T1, $T0, L_ecb_dec_256

    ret
.size rv64i_zvkned_ecb_decrypt,.-rv64i_zvkned_ecb_decrypt
___

$code .= <<___;
.p2align 3
L_ecb_dec_128:
    # Load all 11 round keys to v1-v11 registers.
    @{[aes_128_load_key $KEYP]}

1:
    vsetvli $VL, $LEN32, e32, m4, ta, ma
    slli $T0, $VL, 2
    sub $LEN32, $LEN32, $VL

    vle32.v $V24, ($INP)

    # AES body
    @{[aes_128_decrypt]}

    vse32.v $V24, ($OUTP)

    add $INP, $INP, $T0
    add $OUTP, $OUTP, $T0

    bnez $LEN32, 1b

    ret
.size L_ecb_dec_128,.-L_ecb_dec_128
___

$code .= <<___;
.p2align 3
L_ecb_dec_192:
    # Load all 13 round keys to v1-v13 registers.
    @{[aes_192_load_key $KEYP]}

1:
    vsetvli $VL, $LEN32, e32, m4, ta, ma
    slli $T0, $VL, 2
    sub $LEN32, $LEN32, $VL

    vle32.v $V24, ($INP)

    # AES body
    @{[aes_192_decrypt]}

    vse32.v $V24, ($OUTP)

    add $INP, $INP, $T0
    add $OUTP, $OUTP, $T0

    bnez $LEN32, 1b

    ret
.size L_ecb_dec_192,.-L_ecb_dec_192
___

$code .= <<___;
.p2align 3
L_ecb_dec_256:
    # Load all 15 round keys to v1-v15 registers.
    @{[aes_256_load_key $KEYP]}

1:
    vsetvli $VL, $LEN32, e32, m4, ta, ma
    slli $T0, $VL, 2
    sub $LEN32, $LEN32, $VL

    vle32.v $V24, ($INP)

    # AES body
    @{[aes_256_decrypt]}

    vse32.v $V24, ($OUTP)

    add $INP, $INP, $T0
    add $OUTP, $OUTP, $T0

    bnez $LEN32, 1b

    ret
.size L_ecb_dec_256,.-L_ecb_dec_256
___
}

{
################################################################################
# void rv64i_zvkned_encrypt(const unsigned char *in, unsigned char *out,
#                           const AES_KEY *key);
my ($INP, $OUTP, $KEYP) = ("a0", "a1", "a2");
my ($T0) = ("t0");
my ($KEY_LEN) = ("a3");

$code .= <<___;
.p2align 3
.globl rv64i_zvkned_encrypt
.type rv64i_zvkned_encrypt,\@function
rv64i_zvkned_encrypt:
    # Load key length.
    lwu $KEY_LEN, 480($KEYP)

    # Get proper routine for key length.
    li $T0, 32
    beq $KEY_LEN, $T0, L_enc_256
    li $T0, 24
    beq $KEY_LEN, $T0, L_enc_192
    li $T0, 16
    beq $KEY_LEN, $T0, L_enc_128

    j L_fail_m2
.size rv64i_zvkned_encrypt,.-rv64i_zvkned_encrypt
___

$code .= <<___;
.p2align 3
L_enc_128:
    vsetivli zero, 4, e32, m1, ta, ma

    vle32.v $V1, ($INP)

    vle32.v $V10, ($KEYP)
    vaesz.vs $V1, $V10    # with round key w[ 0, 3]
    addi $KEYP, $KEYP, 16
    vle32.v $V11, ($KEYP)
    vaesem.vs $V1, $V11   # with round key w[ 4, 7]
    addi $KEYP, $KEYP, 16
    vle32.v $V12, ($KEYP)
    vaesem.vs $V1, $V12   # with round key w[ 8,11]
    addi $KEYP, $KEYP, 16
    vle32.v $V13, ($KEYP)
    vaesem.vs $V1, $V13   # with round key w[12,15]
    addi $KEYP, $KEYP, 16
    vle32.v $V14, ($KEYP)
    vaesem.vs $V1, $V14   # with round key w[16,19]
    addi $KEYP, $KEYP, 16
    vle32.v $V15, ($KEYP)
    vaesem.vs $V1, $V15   # with round key w[20,23]
    addi $KEYP, $KEYP, 16
    vle32.v $V16, ($KEYP)
    vaesem.vs $V1, $V16   # with round key w[24,27]
    addi $KEYP, $KEYP, 16
    vle32.v $V17, ($KEYP)
    vaesem.vs $V1, $V17   # with round key w[28,31]
    addi $KEYP, $KEYP, 16
    vle32.v $V18, ($KEYP)
    vaesem.vs $V1, $V18   # with round key w[32,35]
    addi $KEYP, $KEYP, 16
    vle32.v $V19, ($KEYP)
    vaesem.vs $V1, $V19   # with round key w[36,39]
    addi $KEYP, $KEYP, 16
    vle32.v $V20, ($KEYP)
    vaesef.vs $V1, $V20   # with round key w[40,43]

    vse32.v $V1, ($OUTP)

    ret
.size L_enc_128,.-L_enc_128
___

$code .= <<___;
.p2align 3
L_enc_192:
    vsetivli zero, 4, e32, m1, ta, ma

    vle32.v $V1, ($INP)

    vle32.v $V10, ($KEYP)
    vaesz.vs $V1, $V10
    addi $KEYP, $KEYP, 16
    vle32.v $V11, ($KEYP)
    vaesem.vs $V1, $V11
    addi $KEYP, $KEYP, 16
    vle32.v $V12, ($KEYP)
    vaesem.vs $V1, $V12
    addi $KEYP, $KEYP, 16
    vle32.v $V13, ($KEYP)
    vaesem.vs $V1, $V13
    addi $KEYP, $KEYP, 16
    vle32.v $V14, ($KEYP)
    vaesem.vs $V1, $V14
    addi $KEYP, $KEYP, 16
    vle32.v $V15, ($KEYP)
    vaesem.vs $V1, $V15
    addi $KEYP, $KEYP, 16
    vle32.v $V16, ($KEYP)
    vaesem.vs $V1, $V16
    addi $KEYP, $KEYP, 16
    vle32.v $V17, ($KEYP)
    vaesem.vs $V1, $V17
    addi $KEYP, $KEYP, 16
    vle32.v $V18, ($KEYP)
    vaesem.vs $V1, $V18
    addi $KEYP, $KEYP, 16
    vle32.v $V19, ($KEYP)
    vaesem.vs $V1, $V19
    addi $KEYP, $KEYP, 16
    vle32.v $V20, ($KEYP)
    vaesem.vs $V1, $V20
    addi $KEYP, $KEYP, 16
    vle32.v $V21, ($KEYP)
    vaesem.vs $V1, $V21
    addi $KEYP, $KEYP, 16
    vle32.v $V22, ($KEYP)
    vaesef.vs $V1, $V22

    vse32.v $V1, ($OUTP)
    ret
.size L_enc_192,.-L_enc_192
___

$code .= <<___;
.p2align 3
L_enc_256:
    vsetivli zero, 4, e32, m1, ta, ma

    vle32.v $V1, ($INP)

    vle32.v $V10, ($KEYP)
    vaesz.vs $V1, $V10
    addi $KEYP, $KEYP, 16
    vle32.v $V11, ($KEYP)
    vaesem.vs $V1, $V11
    addi $KEYP, $KEYP, 16
    vle32.v $V12, ($KEYP)
    vaesem.vs $V1, $V12
    addi $KEYP, $KEYP, 16
    vle32.v $V13, ($KEYP)
    vaesem.vs $V1, $V13
    addi $KEYP, $KEYP, 16
    vle32.v $V14, ($KEYP)
    vaesem.vs $V1, $V14
    addi $KEYP, $KEYP, 16
    vle32.v $V15, ($KEYP)
    vaesem.vs $V1, $V15
    addi $KEYP, $KEYP, 16
    vle32.v $V16, ($KEYP)
    vaesem.vs $V1, $V16
    addi $KEYP, $KEYP, 16
    vle32.v $V17, ($KEYP)
    vaesem.vs $V1, $V17
    addi $KEYP, $KEYP, 16
    vle32.v $V18, ($KEYP)
    vaesem.vs $V1, $V18
    addi $KEYP, $KEYP, 16
    vle32.v $V19, ($KEYP)
    vaesem.vs $V1, $V19
    addi $KEYP, $KEYP, 16
    vle32.v $V20, ($KEYP)
    vaesem.vs $V1, $V20
    addi $KEYP, $KEYP, 16
    vle32.v $V21, ($KEYP)
    vaesem.vs $V1, $V21
    addi $KEYP, $KEYP, 16
    vle32.v $V22, ($KEYP)
    vaesem.vs $V1, $V22
    addi $KEYP, $KEYP, 16
    vle32.v $V23, ($KEYP)
    vaesem.vs $V1, $V23
    addi $KEYP, $KEYP, 16
    vle32.v $V24, ($KEYP)
    vaesef.vs $V1, $V24

    vse32.v $V1, ($OUTP)
    ret
.size L_enc_256,.-L_enc_256
___

################################################################################
# void rv64i_zvkned_decrypt(const unsigned char *in, unsigned char *out,
#                           const AES_KEY *key);
$code .= <<___;
.p2align 3
.globl rv64i_zvkned_decrypt
.type rv64i_zvkned_decrypt,\@function
rv64i_zvkned_decrypt:
    # Load key length.
    lwu $KEY_LEN, 480($KEYP)

    # Get proper routine for key length.
    li $T0, 32
    beq $KEY_LEN, $T0, L_dec_256
    li $T0, 24
    beq $KEY_LEN, $T0, L_dec_192
    li $T0, 16
    beq $KEY_LEN, $T0, L_dec_128

    j L_fail_m2
.size rv64i_zvkned_decrypt,.-rv64i_zvkned_decrypt
___

$code .= <<___;
.p2align 3
L_dec_128:
    vsetivli zero, 4, e32, m1, ta, ma

    vle32.v $V1, ($INP)

    addi $KEYP, $KEYP, 160
    vle32.v $V20, ($KEYP)
    vaesz.vs $V1, $V20    # with round key w[40,43]
    addi $KEYP, $KEYP, -16
    vle32.v $V19, ($KEYP)
    vaesdm.vs $V1, $V19   # with round key w[36,39]
    addi $KEYP, $KEYP, -16
    vle32.v $V18, ($KEYP)
    vaesdm.vs $V1, $V18   # with round key w[32,35]
    addi $KEYP, $KEYP, -16
    vle32.v $V17, ($KEYP)
    vaesdm.vs $V1, $V17   # with round key w[28,31]
    addi $KEYP, $KEYP, -16
    vle32.v $V16, ($KEYP)
    vaesdm.vs $V1, $V16   # with round key w[24,27]
    addi $KEYP, $KEYP, -16
    vle32.v $V15, ($KEYP)
    vaesdm.vs $V1, $V15   # with round key w[20,23]
    addi $KEYP, $KEYP, -16
    vle32.v $V14, ($KEYP)
    vaesdm.vs $V1, $V14   # with round key w[16,19]
    addi $KEYP, $KEYP, -16
    vle32.v $V13, ($KEYP)
    vaesdm.vs $V1, $V13   # with round key w[12,15]
    addi $KEYP, $KEYP, -16
    vle32.v $V12, ($KEYP)
    vaesdm.vs $V1, $V12   # with round key w[ 8,11]
    addi $KEYP, $KEYP, -16
    vle32.v $V11, ($KEYP)
    vaesdm.vs $V1, $V11   # with round key w[ 4, 7]
    addi $KEYP, $KEYP, -16
    vle32.v $V10, ($KEYP)
    vaesdf.vs $V1, $V10   # with round key w[ 0, 3]

    vse32.v $V1, ($OUTP)

    ret
.size L_dec_128,.-L_dec_128
___

$code .= <<___;
.p2align 3
L_dec_192:
    vsetivli zero, 4, e32, m1, ta, ma

    vle32.v $V1, ($INP)

    addi $KEYP, $KEYP, 192
    vle32.v $V22, ($KEYP)
    vaesz.vs $V1, $V22    # with round key w[48,51]
    addi $KEYP, $KEYP, -16
    vle32.v $V21, ($KEYP)
    vaesdm.vs $V1, $V21   # with round key w[44,47]
    addi $KEYP, $KEYP, -16
    vle32.v $V20, ($KEYP)
    vaesdm.vs $V1, $V20   # with round key w[40,43]
    addi $KEYP, $KEYP, -16
    vle32.v $V19, ($KEYP)
    vaesdm.vs $V1, $V19   # with round key w[36,39]
    addi $KEYP, $KEYP, -16
    vle32.v $V18, ($KEYP)
    vaesdm.vs $V1, $V18   # with round key w[32,35]
    addi $KEYP, $KEYP, -16
    vle32.v $V17, ($KEYP)
    vaesdm.vs $V1, $V17   # with round key w[28,31]
    addi $KEYP, $KEYP, -16
    vle32.v $V16, ($KEYP)
    vaesdm.vs $V1, $V16   # with round key w[24,27]
    addi $KEYP, $KEYP, -16
    vle32.v $V15, ($KEYP)
    vaesdm.vs $V1, $V15   # with round key w[20,23]
    addi $KEYP, $KEYP, -16
    vle32.v $V14, ($KEYP)
    vaesdm.vs $V1, $V14   # with round key w[16,19]
    addi $KEYP, $KEYP, -16
    vle32.v $V13, ($KEYP)
    vaesdm.vs $V1, $V13   # with round key w[12,15]
    addi $KEYP, $KEYP, -16
    vle32.v $V12, ($KEYP)
    vaesdm.vs $V1, $V12   # with round key w[ 8,11]
    addi $KEYP, $KEYP, -16
    vle32.v $V11, ($KEYP)
    vaesdm.vs $V1, $V11   # with round key w[ 4, 7]
    addi $KEYP, $KEYP, -16
    vle32.v $V10, ($KEYP)
    vaesdf.vs $V1, $V10   # with round key w[ 0, 3]

    vse32.v $V1, ($OUTP)

    ret
.size L_dec_192,.-L_dec_192
___

$code .= <<___;
.p2align 3
L_dec_256:
    vsetivli zero, 4, e32, m1, ta, ma

    vle32.v $V1, ($INP)

    addi $KEYP, $KEYP, 224
    vle32.v $V24, ($KEYP)
    vaesz.vs $V1, $V24    # with round key w[56,59]
    addi $KEYP, $KEYP, -16
    vle32.v $V23, ($KEYP)
    vaesdm.vs $V1, $V23   # with round key w[52,55]
    addi $KEYP, $KEYP, -16
    vle32.v $V22, ($KEYP)
    vaesdm.vs $V1, $V22   # with round key w[48,51]
    addi $KEYP, $KEYP, -16
    vle32.v $V21, ($KEYP)
    vaesdm.vs $V1, $V21   # with round key w[44,47]
    addi $KEYP, $KEYP, -16
    vle32.v $V20, ($KEYP)
    vaesdm.vs $V1, $V20   # with round key w[40,43]
    addi $KEYP, $KEYP, -16
    vle32.v $V19, ($KEYP)
    vaesdm.vs $V1, $V19   # with round key w[36,39]
    addi $KEYP, $KEYP, -16
    vle32.v $V18, ($KEYP)
    vaesdm.vs $V1, $V18   # with round key w[32,35]
    addi $KEYP, $KEYP, -16
    vle32.v $V17, ($KEYP)
    vaesdm.vs $V1, $V17   # with round key w[28,31]
    addi $KEYP, $KEYP, -16
    vle32.v $V16, ($KEYP)
    vaesdm.vs $V1, $V16   # with round key w[24,27]
    addi $KEYP, $KEYP, -16
    vle32.v $V15, ($KEYP)
    vaesdm.vs $V1, $V15   # with round key w[20,23]
    addi $KEYP, $KEYP, -16
    vle32.v $V14, ($KEYP)
    vaesdm.vs $V1, $V14   # with round key w[16,19]
    addi $KEYP, $KEYP, -16
    vle32.v $V13, ($KEYP)
    vaesdm.vs $V1, $V13   # with round key w[12,15]
    addi $KEYP, $KEYP, -16
    vle32.v $V12, ($KEYP)
    vaesdm.vs $V1, $V12   # with round key w[ 8,11]
    addi $KEYP, $KEYP, -16
    vle32.v $V11, ($KEYP)
    vaesdm.vs $V1, $V11   # with round key w[ 4, 7]
    addi $KEYP, $KEYP, -16
    vle32.v $V10, ($KEYP)
    vaesdf.vs $V1, $V10   # with round key w[ 0, 3]

    vse32.v $V1, ($OUTP)

    ret
.size L_dec_256,.-L_dec_256
___
}

$code .= <<___;
L_fail_m1:
    li a0, -1
    ret
.size L_fail_m1,.-L_fail_m1

L_fail_m2:
    li a0, -2
    ret
.size L_fail_m2,.-L_fail_m2

L_end:
  ret
.size L_end,.-L_end
___

print $code;

close STDOUT or die "error closing STDOUT: $!";
