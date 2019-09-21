# FileCrypter
A sympathic recursive File Crypter to crypt your directories, subdirectories in AES doubled of an RSA

This tool allow you to crypt data.

There is no graphical interface : only console;)

The command is the following : 

script.jar [path_to_dir_or_files] [action]
[path_to_dir_or_file]  /home/...
[action] : rsa, crypter, decrypter

If you set the path to a file, this one will be crypt in AES 128 for the moment if 256 is not to long I'll add it
If you set the path to a directory, the directory and all subdirictories will be encrypted
<!>You must give 2 arguments to the script<!>


The functionment is the following:
-You need to generate a rsa 1024 couple of keys first thanks to the argument "rsa". public and private key are going to be written in 2 different files in the same directory of the jar : keys.pub and keys.priv
-When you will crypt thanks to the "crypter" argument an aes key is generated and the path you set is going to be encrypted thanks to this key.
-The AES key is going to be encrypted thanks to the RSA public key and will be stored in the keys.enc file, same location than the .jar
-The data is then encrypted with this key

When you decrypt its just the reverse process. Howewer take care that the keys.priv and the keys.enc you used for encryption are in the same folder than the .jar
