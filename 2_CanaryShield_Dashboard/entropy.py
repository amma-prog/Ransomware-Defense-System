import math

def calculate_shannon_entropy(filepath):
    """
    Calcule l'entropie de Shannon pour le fichier donné.
    Retourne une valeur entre 0.0 et 8.0.
    """
    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        if not data:
            return 0.0

        entropy = 0
        length = len(data)
        
        # Compter les occurrences de chaque octet (0-255)
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
            
        # Calcul de l'entropie de Shannon
        for count in byte_counts:
            if count == 0:
                continue
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    except Exception as e:
        print(f"Erreur lors du calcul de l'entropie pour {filepath}: {e}")
        return 0.0
