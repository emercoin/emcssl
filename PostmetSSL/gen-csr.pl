#!/usr/local/bin/perl -w
# Generate CSR request to Postmet for SSL-certificate for your domain
# in the emerDNS alternative domain zones.
# To generate, run this program with paremeter - your domain, for example:
#   ./gen-csr.pl my-domain.emc
# Before usage, edit file req_san_template.conf, change fields: C/ST/L/O/OU
# After generated, submit freshly generate CSR for to: https://www.postmet.com/csr/

my $domain = $ARGV[0];

die "Usage:\n\t $0 your_domain_name\n\n" unless defined $domain;

open(SAMPLE, "req_san_template.conf") || die "Unable to open req_san_template.conf, reason: $!\n";
open(CF, ">$domain.cf") || die "Unable to write $domain.cf, reason: $!\n";
while(<SAMPLE>) {
    s/domain\.lib/$domain/g;
    print CF;
}
close CF;

# Orig RSA request from Postmet
# exec "openssl req -new -out $domain.csr -newkey rsa:2048 -nodes -sha256 -keyout $domain.key -config $domain.san";

exec "openssl ecparam -out  $domain.key -name secp256k1 -genkey && "
   . "openssl req -new -key $domain.key -out $domain.csr -sha256 -config $domain.cf"

