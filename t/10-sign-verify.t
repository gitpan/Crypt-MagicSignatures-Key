#!/usr/bin/env perl
use Test::More tests => 12;
use strict;
use warnings;
no strict 'refs';

use lib '../lib';

our $module;
BEGIN {
  our $module = 'Crypt::MagicSignatures::Key';
  use_ok($module, qw/b64url_encode b64url_decode/);   # 1
};

# MiniMe-Test (Key)
my $encodedPrivateKey = 'RSA.hkwS0EK5Mg1dpwA4shK5FNtHmo9F7sIP6gKJ5fyFWNotO'.
  'bbbckq4dk4dhldMKF42b2FPsci109MF7NsdNYQ0kXd3jNs9VLCHUujxiafVjhw06hFNWBmv'.
  'ptZud7KouRHz4Eq2sB-hM75MEn3IJElOquYzzUHi7Q2AMalJvIkG26c=.AQAB.JrT8YywoB'.
  'oYVrRGCRcjhsWI2NBUBWfxy68aJilEK-f4ANPdALqPcoLSJC_RTTftBgz6v4pTv2zqiJY9N'.
  'zuPo5mijN4jJWpCA-3HOr9w8Kf8uLwzMVzNJNWD_cCqS5XjWBwWTObeMexrZTgYqhymbfxx'.
  'z6Nqxx352oPh4vycnXOk=';

my $mkey = Crypt::MagicSignatures::Key->new($encodedPrivateKey);

is($mkey->size, 1024, 'Correct key size');

my $sig;
my $msg = 'this_is_a_signedmessage';

ok($sig = $mkey->sign($msg), 'Signed');
ok($mkey->verify($msg, $sig), 'Verified');
ok(!$mkey->verify('a' . $msg, $sig), 'Not verified');

$msg = 'This is an arbitrary length text';
ok($sig = $mkey->sign($msg), 'Signed');
ok($mkey->verify($msg, $sig), 'Verified');
ok(!$mkey->verify(' ' . $msg, $sig), 'Not verified');

$msg = '                                   ';
ok($sig = $mkey->sign($msg), 'Signed');
ok($mkey->verify($msg, $sig), 'Verified');
ok(!$mkey->verify(' ' . $msg, $sig), 'Not verified');

{
  local $SIG{__WARN__} = sub {};
  ok(!$mkey->verify($msg, $sig . 'u'), 'Not verified');
};

