#!/bin/sh 

FNAME=$1
if [ ! -s "$FNAME" ] ; then
    echo "Use parameter: Certificate_template_*.tpl [EC|RSA]"
    exit
fi

CA_TYPE=$2
if [ -z "$CA_TYPE" ] ; then
    CA_TYPE="EC"
fi

CA_DIR=CA-${CA_TYPE}

SERIAL="${FNAME%.*}"

SUBJ=`head -1 $FNAME`

rm -rf db
mkdir db db/certs db/newcerts
touch db/index.txt
echo $SERIAL > db/serial

openssl req -new -newkey rsa:2048 -nodes -keyout $SERIAL.key \
 -subj "$SUBJ" \
 -out $SERIAL.csr

#openssl ecparam -genkey -name secp256k1 -out $SERIAL.key
#openssl req -new -key $SERIAL.key -subj "$SUBJ" -out $SERIAL.csr

openssl ca -config $CA_DIR/ca.config -in $SERIAL.csr -out $SERIAL.crt -batch || exit 1

echo
echo "Please, enter password for certificate package."
echo "You will use this password, when install certificate into browser"

openssl pkcs12 -export -in $SERIAL.crt -inkey $SERIAL.key \
            -certfile $CA_DIR/emcssl_ca.crt -out $SERIAL.p12  || exit 1

#openssl x509 -noout -text -in $SERIAL.crt

echo "Your new ${CA_TYPE}-certificate in the file $SERIAL.p12"

rm -rf db $SERIAL.csr $SERIAL.key

#SHA256=`openssl x509 -noout -in $SERIAL.crt -fingerprint -sha256 | sed 's/^.* //'`
SHA256=`openssl x509 -noout -in $SERIAL.crt -fingerprint -sha256 | sed 's/://g' | tr '[:upper:]' '[:lower:]'`
SHA256=${SHA256#'sha256 fingerprint='}

echo $SHA256 >>$FNAME

echo
echo "Please, deposit into EmerCoin NVS pair:"
echo "  Key:   ssl:$SERIAL"
echo "  Value: sha256=$SHA256"

