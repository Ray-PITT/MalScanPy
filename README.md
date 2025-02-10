# 🚀 MalScanPy - Analyse Statique de Fichiers Exécutables  

MalScanPy est un script Python permettant d'extraire **des informations statiques** sur les fichiers exécutables **PE (Windows)**.  
Il est encore en développement et évoluera progressivement.  

---

## 📌 Fonctionnalités  

✅ Extraction des **sections du fichier** (nom, taille, adresse mémoire)  
✅ Calcul du **hash SHA-256** du fichier  
✅ Liste des **imports (DLL et fonctions utilisées)**  

📌 **Fonctionnalités à venir** :  
🔹 Vérification des **sections suspectes**  
🔹 Extraction des **chaînes de caractères**  
🔹 Scan avec **YARA** pour détecter les malwares  

---

## 📌 Installation  

### 1️⃣ **Prérequis**  
- **Python 3.8+**  
- Installation des dépendances :  

```bash
pip install lief
```


### 2️⃣ Vérification de l’installation

Tester si lief est bien installé :
```bash
import lief
print(lief.__version__)  # Doit afficher la version installée
```
