#se

A searchable encryption written in Python.


##About folder
1.data folder includes:
		a.ciphertext files folder: store ciphertexts 
		b.files folder: original files in plaintext
		c.index.txt: encrypted inverted index
		d.skaes.txt: secret key for AES-CBC-256
		f.skprf.txt: it is empty. Use SHA-256 for PRF
		token.txt: encrypted keyword



2.src folder include pow.py
		a.se.py : searchable encryption algo implementation
		b.aes1.py : aes algo  


2.results folder include running_time, solution, target
		a.result.txt : search result


	

##Usage

1. place source original files into '../data/files/'  folder
2. Then running the ‘se.py' script
3. Input the search keyword in the command line 




### Dependencies

	*IDE[PyCharm]
	*[Python 2.7]
	*MAC, 2.5GHz Intel Core i5, 12GB memory,

