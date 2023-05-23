# jacuzzi_decrypt
Simple Python script to decrypt type "C4", "CA' and "CC" message types from "encrypted" Jacuzzi and Sundance Spa Controllers.

Some versions of Jacuzzi and Sundance hot tub control boards are "encrypted" which makes them incompatible with non-encrypted devices.  This simple Python script illustrates the decryption algorithm and also serves as a simple command line tool you can use to decrypt messages by hand.

Example Command Line:

python3 decrypt.py 7e26ffafc4eee7aaebe4e14e1de7a184e1dcfd6efa9ff9fbecf4f0ddf758f1f292aaedcecfc8357e

Of course you can also include the decryption script in your own Python code.

The message strings should be complete message packets with everything, including the header and trailing "7e" bytes. Only messages of type C4, CA and CC will be decrypted; any others are returned unchanged.

# Credits/References
- https://github.com/garbled1/pybalboa
- https://github.com/HyperActiveJ/sundance780-jacuzzi-balboa-rs485-tcp/blob/master/pybalboa/sundanceRS485.py
- https://github.com/jackbrown1993/Jacuzzi-RS485
