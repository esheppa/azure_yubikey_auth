# Yubi PIV

* Use ykman for everything, yubico-piv-tool seems to be broken

## Setup
Set pins as per: https://developers.yubico.com/PIV/Guides/Device_setup.html

Generate the key-pair
`ykman piv keys generate -a RSA2048 --touch-policy ALWAYS --pin-policy ONCE 9c 9c.pub`


Generate the self-signed certificate (not a CSR...)
`ykman piv certificates generate -a SHA256 -s 'YUBI' 9c 9c.pub`

Export the self-signed certificate
`ykman piv certificates export 9c -`
