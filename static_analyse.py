import vt
import time
import hashlib 
import lief

VS_API_KEY = ""
FILE_PATH = ""



# Get the hash of the file
def get_file_hash(file_path):
    hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096),b""):
            hash.update(byte_block)
    return hash.hexdigest()

# Get the analysis of the file from virustotal
def get_file_analysis(API_KEY):
    client = vt.Client(API_KEY) 
    hash = get_file_hash(FILE_PATH) #input the file like on the website 
    sep = FILE_PATH.split("/")
    file = client.get_object("/files/{}".format(hash)) #get the file from the hash
    dico = {"file_name":sep[-1],"hash": hash, "type": file.type, "size": file.size, "first_analysis_date": file.first_analysis_date, "last_analysis_date": file.last_analysis_date, "last_analysis_stats": file.last_analysis_stats}
    client.close()
    return dico



def lief_analysis(FILE_PATH):
    pe = lief.parse(FILE_PATH)
    dll =[i.name for i in pe.imports]

    dico = {"signature": pe.has_signature, "dll": dll}
    return dico

def section(FILE_PATH):
    pe = lief.parse(FILE_PATH)
    section = []
    for i in pe.sections:
        section.append(i.name)
        section.append(i.virtual_address)
        section.append(i.virtual_size)
        section.append(i.size)
        section.append(i.characteristics)
    return section
    
   #Sections du fichier → Identifier les parties du fichier binaire (utile pour les exécutables).
   #Chaînes de caractères lisibles → Extraire des URLs, clés de registre, commandes intégrées.