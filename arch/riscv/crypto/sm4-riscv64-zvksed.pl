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

# The generated code of this file depends on the following RISC-V extensions:
# - RV64I
# - RISC-V Vector ('V') with VLEN >= 128
# - RISC-V Vector SM4 Block Cipher extension ('Zvksed')
# - RISC-V Vector Cryptography Bit-manipulation extension ('Zvkb')

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
.option arch, +zvksed, +zvkb
___

####
# int rv64i_zvksed_sm4_set_key(const u8 *user_key, unsigned int key_len,
#			                         u32 *enc_key, u32 *dec_key);
#
{
my ($ukey,$key_len,$enc_key,$dec_key)=("a0","a1","a2","a3");
my ($fk,$stride)=("a4","a5");
my ($t0,$t1)=("t0","t1");
my ($vukey,$vfk,$vk0,$vk1,$vk2,$vk3,$vk4,$vk5,$vk6,$vk7)=("v1","v2","v3","v4","v5","v6","v7","v8","v9","v10");
$code .= <<___;
.p2align 3
.globl rv64i_zvksed_sm4_set_key
.type rv64i_zvksed_sm4_set_key,\@function
rv64i_zvksed_sm4_set_key:
    li $t0, 16
    beq $t0, $key_len, 1f
    li a0, 1
    ret
1:

    vsetivli zero, 4, e32, m1, ta, ma

    # Load the user key
    vle32.v $vukey, ($ukey)
    vrev8.v $vukey, $vukey

    # Load the FK.
    la $fk, FK
    vle32.v $vfk, ($fk)

    # Generate round keys.
    vxor.vv $vukey, $vukey, $vfk
    vsm4k.vi $vk0, $vukey, 0 # rk[0:3]
    vsm4k.vi $vk1, $vk0, 1 # rk[4:7]
    vsm4k.vi $vk2, $vk1, 2 # rk[8:11]
    vsm4k.vi $vk3, $vk2, 3 # rk[12:15]
    vsm4k.vi $vk4, $vk3, 4 # rk[16:19]
    vsm4k.vi $vk5, $vk4, 5 # rk[20:23]
    vsm4k.vi $vk6, $vk5, 6 # rk[24:27]
    vsm4k.vi $vk7, $vk6, 7 # rk[28:31]

    # Store enc round keys
    vse32.v $vk0, ($enc_key) # rk[0:3]
    addi $enc_key, $enc_key, 16
    vse32.v $vk1, ($enc_key) # rk[4:7]
    addi $enc_key, $enc_key, 16
    vse32.v $vk2, ($enc_key) # rk[8:11]
    addi $enc_key, $enc_key, 16
    vse32.v $vk3, ($enc_key) # rk[12:15]
    addi $enc_key, $enc_key, 16
    vse32.v $vk4, ($enc_key) # rk[16:19]
    addi $enc_key, $enc_key, 16
    vse32.v $vk5, ($enc_key) # rk[20:23]
    addi $enc_key, $enc_key, 16
    vse32.v $vk6, ($enc_key) # rk[24:27]
    addi $enc_key, $enc_key, 16
    vse32.v $vk7, ($enc_key) # rk[28:31]

    # Store dec round keys in reverse order
    addi $dec_key, $dec_key, 12
    li $stride, -4
    vsse32.v $vk7, ($dec_key), $stride # rk[31:28]
    addi $dec_key, $dec_key, 16
    vsse32.v $vk6, ($dec_key), $stride # rk[27:24]
    addi $dec_key, $dec_key, 16
    vsse32.v $vk5, ($dec_key), $stride # rk[23:20]
    addi $dec_key, $dec_key, 16
    vsse32.v $vk4, ($dec_key), $stride # rk[19:16]
    addi $dec_key, $dec_key, 16
    vsse32.v $vk3, ($dec_key), $stride # rk[15:12]
    addi $dec_key, $dec_key, 16
    vsse32.v $vk2, ($dec_key), $stride # rk[11:8]
    addi $dec_key, $dec_key, 16
    vsse32.v $vk1, ($dec_key), $stride # rk[7:4]
    addi $dec_key, $dec_key, 16
    vsse32.v $vk0, ($dec_key), $stride # rk[3:0]

    li a0, 0
    ret
.size rv64i_zvksed_sm4_set_key,.-rv64i_zvksed_sm4_set_key
___
}

####
# void rv64i_zvksed_sm4_encrypt(const unsigned char *in, unsigned char *out,
#                               const SM4_KEY *key);
#
{
my ($in,$out,$keys,$stride)=("a0","a1","a2","t0");
my ($vdata,$vk0,$vk1,$vk2,$vk3,$vk4,$vk5,$vk6,$vk7,$vgen)=("v1","v2","v3","v4","v5","v6","v7","v8","v9","v10");
$code .= <<___;
.p2align 3
.globl rv64i_zvksed_sm4_encrypt
.type rv64i_zvksed_sm4_encrypt,\@function
rv64i_zvksed_sm4_encrypt:
    vsetivli zero, 4, e32, m1, ta, ma

    # Load input data
    vle32.v $vdata, ($in)
    vrev8.v $vdata, $vdata

    # Order of elements was adjusted in sm4_set_key()
    # Encrypt with all keys
    vle32.v $vk0, ($keys) # rk[0:3]
    vsm4r.vs $vdata, $vk0
    addi $keys, $keys, 16
    vle32.v $vk1, ($keys) # rk[4:7]
    vsm4r.vs $vdata, $vk1
    addi $keys, $keys, 16
    vle32.v $vk2, ($keys) # rk[8:11]
    vsm4r.vs $vdata, $vk2
    addi $keys, $keys, 16
    vle32.v $vk3, ($keys) # rk[12:15]
    vsm4r.vs $vdata, $vk3
    addi $keys, $keys, 16
    vle32.v $vk4, ($keys) # rk[16:19]
    vsm4r.vs $vdata, $vk4
    addi $keys, $keys, 16
    vle32.v $vk5, ($keys) # rk[20:23]
    vsm4r.vs $vdata, $vk5
    addi $keys, $keys, 16
    vle32.v $vk6, ($keys) # rk[24:27]
    vsm4r.vs $vdata, $vk6
    addi $keys, $keys, 16
    vle32.v $vk7, ($keys) # rk[28:31]
    vsm4r.vs $vdata, $vk7

    # Save the ciphertext (in reverse element order)
    vrev8.v $vdata, $vdata
    li $stride, -4
    addi $out, $out, 12
    vsse32.v $vdata, ($out), $stride

    ret
.size rv64i_zvksed_sm4_encrypt,.-rv64i_zvksed_sm4_encrypt
___
}

####
# void rv64i_zvksed_sm4_decrypt(const unsigned char *in, unsigned char *out,
#                               const SM4_KEY *key);
#
{
my ($in,$out,$keys,$stride)=("a0","a1","a2","t0");
my ($vdata,$vk0,$vk1,$vk2,$vk3,$vk4,$vk5,$vk6,$vk7,$vgen)=("v1","v2","v3","v4","v5","v6","v7","v8","v9","v10");
$code .= <<___;
.p2align 3
.globl rv64i_zvksed_sm4_decrypt
.type rv64i_zvksed_sm4_decrypt,\@function
rv64i_zvksed_sm4_decrypt:
    vsetivli zero, 4, e32, m1, ta, ma

    # Load input data
    vle32.v $vdata, ($in)
    vrev8.v $vdata, $vdata

    # Order of key elements was adjusted in sm4_set_key()
    # Decrypt with all keys
    vle32.v $vk7, ($keys) # rk[31:28]
    vsm4r.vs $vdata, $vk7
    addi $keys, $keys, 16
    vle32.v $vk6, ($keys) # rk[27:24]
    vsm4r.vs $vdata, $vk6
    addi $keys, $keys, 16
    vle32.v $vk5, ($keys) # rk[23:20]
    vsm4r.vs $vdata, $vk5
    addi $keys, $keys, 16
    vle32.v $vk4, ($keys) # rk[19:16]
    vsm4r.vs $vdata, $vk4
    addi $keys, $keys, 16
    vle32.v $vk3, ($keys) # rk[15:11]
    vsm4r.vs $vdata, $vk3
    addi $keys, $keys, 16
    vle32.v $vk2, ($keys) # rk[11:8]
    vsm4r.vs $vdata, $vk2
    addi $keys, $keys, 16
    vle32.v $vk1, ($keys) # rk[7:4]
    vsm4r.vs $vdata, $vk1
    addi $keys, $keys, 16
    vle32.v $vk0, ($keys) # rk[3:0]
    vsm4r.vs $vdata, $vk0

    # Save the ciphertext (in reverse element order)
    vrev8.v $vdata, $vdata
    li $stride, -4
    addi $out, $out, 12
    vsse32.v $vdata, ($out), $stride

    ret
.size rv64i_zvksed_sm4_decrypt,.-rv64i_zvksed_sm4_decrypt
___
}

$code .= <<___;
# Family Key (little-endian 32-bit chunks)
.p2align 3
FK:
    .word 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
.size FK,.-FK
___

print $code;

close STDOUT or die "error closing STDOUT: $!";
