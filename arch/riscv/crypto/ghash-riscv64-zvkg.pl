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

# - RV64I
# - RISC-V Vector ('V') with VLEN >= 128
# - RISC-V Vector GCM/GMAC extension ('Zvkg')

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
.option arch, +zvkg
___

###############################################################################
# void gcm_ghash_rv64i_zvkg(be128 *Xi, const be128 *H, const u8 *inp, size_t len)
#
# input: Xi: current hash value
#        H: hash key
#        inp: pointer to input data
#        len: length of input data in bytes (multiple of block size)
# output: Xi: Xi+1 (next hash value Xi)
{
my ($Xi,$H,$inp,$len) = ("a0","a1","a2","a3");
my ($vXi,$vH,$vinp,$Vzero) = ("v1","v2","v3","v4");

$code .= <<___;
.p2align 3
.globl gcm_ghash_rv64i_zvkg
.type gcm_ghash_rv64i_zvkg,\@function
gcm_ghash_rv64i_zvkg:
    vsetivli zero, 4, e32, m1, ta, ma
    vle32.v $vH, ($H)
    vle32.v $vXi, ($Xi)

Lstep:
    vle32.v $vinp, ($inp)
    add $inp, $inp, 16
    add $len, $len, -16
    vghsh.vv $vXi, $vH, $vinp
    bnez $len, Lstep

    vse32.v $vXi, ($Xi)
    ret

.size gcm_ghash_rv64i_zvkg,.-gcm_ghash_rv64i_zvkg
___
}

print $code;

close STDOUT or die "error closing STDOUT: $!";
