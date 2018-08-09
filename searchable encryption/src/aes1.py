# coding: utf8
from Crypto.Cipher import AES
from Crypto import Random
from binascii import b2a_hex, a2b_hex
import os
import pickle
import shutil


class aes():
    def __init__(self):
        self.length = AES.block_size                            #the default block length of AES；
        self.dir = os.path.abspath(os.path.join(os.path.dirname('__file__'), os.path.pardir))

    def KeyGen(self):
        """
        given the default block length of AES, generate a secrect key randomly
        and write to a file in hexadecimal
        :return: sk
        """
        sk = Random.new().read(self.length)
        with open(self.dir + '/data/skaes.txt', 'w') as file:
            file.write(str(b2a_hex(sk)))
        iv = Random.new().read(self.length)
        with open(self.dir + '/data/iv.txt', 'w') as file:
            file.write(str(b2a_hex(iv)))
        print ('secret key is:',str(b2a_hex(sk)))
    
    
    def enc_cbc(self, sk, iv, plaintext):
        """
        generate an iv with certain length (same as default block length of AES) randomly and write to a file
        given sk and plaintext, encrypt plaintext with sk and iv by CBC mode
        :param sk: 
        :param plaintext: 
        :return: c
        """
        cryptor = AES.new(sk, AES.MODE_CBC, iv)
        self.ciphertext = cryptor.encrypt(plaintext)
        c = b2a_hex(iv + self.ciphertext)                 #append ciphertext to iv, return c in hexadecimal
        return c


    def enc_allfiles(self):
        """
        encrypt all data files {f1,f2,f3,f4,...}
        use AES-CBC-256
        write ciphertext to files {c1,c2,c3,c4,...}
        build plaintext file to ciphertext file mapping table. e.g. {['f1':(c1)],['f2':(c2)]...}
        :return: 
        """
        dir = self.dir + '/data/files'
        items = os.listdir(dir)
        file_id =1
        with open(self.dir + '/data/iv.txt', 'r') as file:
            iv = file.read()
            iv = a2b_hex(iv)
        with open(self.dir + '/data/skaes.txt', 'r') as file:
            sk = file.read()

        dir_0 = self.dir + '/data/ciphertext files'
        c_files = os.listdir(dir_0)
        if c_files is not None:
            shutil.rmtree(self.dir + '/data/ciphertext files')
            os.mkdir(self.dir + '/data/ciphertext files')
        for item in items:
            if not item.endswith('.DS_Store'):
                with open(dir + '/' + item, 'r') as file:
                    plaintext = file.read()
                count = len(plaintext)

                "padding plaintext"
                if count < self.length:
                    add = self.length - count
                    plaintext = plaintext + ('\0' * add)
                elif count > self.length:
                    add = (self.length - (count % self.length))
                    plaintext = plaintext + ('\0' * add)

                ciphertext = self.enc_cbc(sk, iv, plaintext)
                filename = 'c' + str(file_id) + '.txt'
                with open(self.dir + '/data/ciphertext files/' + filename, 'w') as file:
                    file.write(ciphertext + ' ')
                file_id += 1


    def dec_cbc(self,sk,c):
        """
        read iv from file
        given sk and c, decrypt c with sk and iv in CBC mode 
        :param sk: 
        :param c: 
        :return: plaintext
        """
        with open(self.dir + '/data/iv.txt', 'r') as file:
            iv = file.read()
            iv = a2b_hex(iv)
        cryptor = AES.new(sk,AES.MODE_CBC, iv)
        plaintext = cryptor.decrypt(a2b_hex(c)[self.length:])       #[self.length:]remove iv from c before decryption
        return plaintext

