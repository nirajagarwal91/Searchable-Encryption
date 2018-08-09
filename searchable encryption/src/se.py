import os
import hashlib
import pickle                                                                                                           # the lib for special format data saving, such as dict...
import aes1
import time

class se:

    def __init__(self):
        self.dir = os.path.abspath(os.path.join(os.path.dirname('__file__'), os.path.pardir))                           #get the parent folder path '../searchable encryption/'

    def build_encrypted_inverted_index(self):
        """
        etract all keywords from folder files
        present inverted index as dic{[file1:(key1,key4)],[file2:(key2,key3)]...}
        encrypt this inverted index
        use SHA256 to simulate PRF
        no sk needed for SHA256
        :return: 
        """
        dic = {}
        dir = self.dir + '/data/files'
        items = os.listdir(dir)
        count = 1
        for item in items:
            if not item.endswith('.DS_Store'):
                with open(dir + '/' + item, 'r') as file:
                    key_list = file.read()
                    key_list = key_list.split()
                for keyword in key_list:
                    if keyword not in dic:                                                                                  # when keyword is new in this dic, then creat a pair[key:(value)] for it
                        dic[keyword] = []
                    c_name = 'c' + str(count) + '.txt'
                    dic[keyword].append(c_name)
                count += 1
        """
        ecrypting dic
        """
        unique_keywords = dic.keys()
        for unique_keyword in unique_keywords:
            token = hashlib.sha256(unique_keyword).hexdigest()
            dic[token] = dic.pop(unique_keyword)                                                                        #replace the keyword in dic with corresponding hash value
        with open(self.dir + '/data/index.txt', 'w') as file:                                                              #save dic as dict format in file use lib "pickle'
            pickle.dump(dic, file)


    def tokenGen(self, keyword):
        """
        given a keyword w
        use SHA256 to enc keyword w
        :return:
        """
        token = hashlib.sha256(keyword).hexdigest()
        print ('The search token is:',token)
        with open(self.dir + '/data/token.txt', 'w') as file:
            file.write(token)

    def searching(self, token, inverted_index, sk):
        """
        given a search token
        with inverted index, sk
        find the correspnding encrypted files 
        decrypt the files 
        write the results to the file
        display the results
        :param token: 
        :param inverted_index: 
        :param sk: 
        :return: 
        """
        result_c_ids = inverted_index.get(token)
        print ('searching result is:', result_c_ids)
        try:
            with open(self.dir + '/result/result.txt', 'r') as file:
                f = file.read()
                if f is not None:
                    os.remove(self.dir + '/result/result.txt')
            if result_c_ids is None:
                with open(self.dir + '/result/result.txt', 'w') as file:
                    file.write('')
            else:
                for result_c_id in result_c_ids:
                    with open(self.dir + '/data/ciphertext files/' + result_c_id, 'r') as file:
                        ciphertexts = file.read()
                        ciphertexts = ciphertexts.split()
                    for c in ciphertexts:
                        plaintext = AES.dec_cbc(sk, c)
                        plaintext = plaintext.strip('\0')
                        with open(self.dir + '/result/result.txt', 'a') as file:
                            file.write(result_c_id + ' ' + plaintext + '\n')
                            print (result_c_id + ' ' + plaintext)
        except IOError:
            if result_c_ids is None:
                with open(self.dir + '/result/result.txt', 'w') as file:
                    file.write('')
            else:
                for result_c_id in result_c_ids:
                    with open(self.dir + '/data/ciphertext files/' + result_c_id, 'r') as file:
                        ciphertexts = file.read()
                        ciphertexts = ciphertexts.split()
                    for c in ciphertexts:
                        plaintext = AES.dec_cbc(sk, c)
                        plaintext = plaintext.strip('\0')
                        with open(self.dir + '/result/result.txt', 'a') as file:
                            file.write(result_c_id + ' ' + plaintext + '\n')
                            print (result_c_id + ' ' + plaintext)


if __name__ == '__main__':
    print ('program running...')
    AES = aes1.aes()
    SE = se()
    """
    1.generate key for AES
    2.encrypt all plaintext files 
    3.build encrypted inverted index 
    """
    AES.KeyGen()
    start_time_0 = time.time()
    AES.enc_allfiles()
    SE.build_encrypted_inverted_index()
    elapse_time_0 = time.time()
    running_time_0 = float('%0.4f' % (elapse_time_0 - start_time_0))

    print ('Running time for encrypting index & files is:' + str(running_time_0) + ' seconds')
    """
    #searching step
    1.input search keyword
    2.generate corresponding token
    3.read token, sk, inverted_index
    4.searching...
    """
    keyword = raw_input('please input the search keyword: ')
    SE.tokenGen(keyword)
    with open(SE.dir + '/data/token.txt', 'r') as file:
        token = file.read()
    with open(SE.dir + '/data/skaes.txt', 'r') as file:
        sk = file.read()
    with open(SE.dir + '/data/index.txt', 'r') as f:
        inverted_index = pickle.load(f)
    start_time_1 = time.time()
    SE.searching(token, inverted_index, sk)
    elapse_time_1 = time.time()
    running_time_1 = float('%0.4f' %(elapse_time_1 - start_time_1))
    print ('Running time for searching & decryting files is:' + str(running_time_1) + ' seconds')