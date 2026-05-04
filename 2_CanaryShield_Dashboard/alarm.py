import winsound
import threading

class AlarmSystem:
    def __init__(self):
        self.is_playing = False
        self._thread = None

    def trigger(self):
        """Lance l'alarme dans un thread séparé pour ne pas bloquer l'interface."""
        if self.is_playing:
            return
        self.is_playing = True
        self._thread = threading.Thread(target=self._play_alarm, daemon=True)
        self._thread.start()

    def stop(self):
        """Arrête l'alarme."""
        self.is_playing = False

    def _play_alarm(self):
        """
        Séquence d'alarme dramatique : 3 cycles de sirène montante/descendante.
        """
        try:
            for cycle in range(3):
                if not self.is_playing:
                    break
                # Sirène montante
                for freq in range(400, 1200, 100):
                    if not self.is_playing:
                        break
                    winsound.Beep(freq, 80)
                # Sirène descendante
                for freq in range(1200, 400, -100):
                    if not self.is_playing:
                        break
                    winsound.Beep(freq, 80)
        except Exception:
            pass
        finally:
            self.is_playing = False
