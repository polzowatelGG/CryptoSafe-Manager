from core.crypto.abstract import EncryptionService

class AES256Placeholder(EncryptionService): 
    def xor_bytes(self, data: bytes, key: bytes) -> bytes: # функция для выполнения операции XOR между данными и ключом / заглушка до спринта 3

        result = bytearray() # преобразовать данные в bytearray для возможности изменения
        for i in range(len(data)):
            result.append(data[i] ^ key[i % len(key)]) # выполнить XOR между каждым байтом данных и соответствующим байтом ключа (циклически)
        return bytes(result) 
    
    def encrypt(self, data: bytes, key: bytes) -> bytes: #зашифровать данные с помощью ключа
        return self.xor_bytes(data, key) 

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes: #расшифровать данные с помощью ключа
        return self.xor_bytes(ciphertext, key) 